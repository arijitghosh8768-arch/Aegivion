# Algorithm #1 — Cloud Credential Compromise Detector

**Part 1: foundation.** This directory currently implements the *plumbing* of the
detector — telemetry normalization, identity resolution, session construction,
identity profiles, configuration and storage. Behavioral features, rules,
baselines, anomaly detection, risk fusion and finding generation are **Part 2**
and are deliberately unimplemented (they raise `NotImplementedYetError` rather
than returning plausible-looking numbers).

> **Design rule.** An LLM never detects. The pipeline is
> `telemetry → normalization → features → rules/anomaly → risk fusion → finding`,
> and the LLM may only *explain* a finding afterwards.

---

## 1. What the detector is trying to answer

> "Is this legitimate cloud identity behaving differently enough from its
> established behavior that its credentials may be compromised?"

It is **not** trying to prove compromise from a single event. It accumulates
multiple independent behavioral signals, so it can fire **before** any data
exfiltration, ransomware or destructive action occurs.

---

## 2. Pipeline position

```
CloudTrail ──► Normalizer ──► Identity Resolution ──► Session Construction
                                                              │
                                        ┌─────────────────────┴─────────────────────┐
                                        ▼                                           ▼
                              IdentityActivityEvent ────────────────► Identity Profiles
                                                                              │
                                            (Part 2) features → rules → anomaly → risk
                                                                              ▼
                                                              Finding ──► ARDE ──► Correlation
```

---

## 3. Repository layout

```
detection/credential_compromise/
    schemas.py     provider-neutral domain models + enums + API taxonomy constants
    normalizer.py  provider-neutral NormalizerRegistry (multi-cloud seam)
    identity.py    raw userIdentity -> ResolvedIdentity + baseline category
    session.py     session keying, continuity rules, streaming SessionTracker
    profile.py     baseline quality grading, cold-start + peer fallback
    features.py    (Part 2) six behavioral features
    rules.py       (Part 2) R001-R012 rule signals
    baseline.py    (Part 2) normal_* distribution aggregation + poisoning guard
    anomaly.py     (Part 2) per-category Isolation Forest
    scorer.py      (Part 2) risk fusion + severity bands
    confidence.py  (Part 2) confidence calibration (confidence != risk)
    finding.py     (Part 2) structured finding assembly
    detector.py    (Part 2) thin end-to-end orchestration
    config.py      environment-driven configuration (no hard-coded scores)
    exceptions.py  typed error hierarchy
    tests/         unit tests + CloudTrail fixtures

ingestion/aws/
    cloudtrail.py  raw CloudTrail -> IdentityActivityEvent (the only place that
                   understands raw CloudTrail JSON)
    enrichment.py  IpEnricher seam (null by default, so nothing is invented)

storage/
    database.py              engine/session bootstrap (SQLite tests, PostgreSQL prod)
    models.py                identity_profiles, identity_events, identity_sessions,
                             behavioral_features, security_findings, baseline_versions
    identity_repository.py   profiles + baseline versions + peer lookup
    event_repository.py      events + sessions (access keys stored as fingerprints)
    finding_repository.py    shared security_findings table

api/credential_compromise.py  router skeleton (endpoints arrive with real findings)
```

---

## 4. Component reference

### `schemas.py` — the provider-neutral contract

`IdentityActivityEvent` is the boundary between ingestion and detection. Nothing
downstream of the normalizer knows what CloudTrail looks like, so Azure and GCP
support later becomes a new normalizer rather than a rewrite.

Key schema decisions:

| Decision | Why |
| --- | --- |
| `region` vs `region_hint` | `region` is the cloud region (`ap-south-1`); `region_hint` is geographic (`Maharashtra`). |
| `identity_key` | Canonical baseline key `provider:account:baseline_category:principal_id`. |
| `baseline_category` | Humans, assumed roles, federated identities, services and machines are never compared to each other. |
| `access_key_id` | Kept in memory only; `to_log_dict()` and `__repr__` redact it, and storage keeps a salted fingerprint. |
| `normalization_warnings` | AWS pseudo-sources (e.g. `AWS Internal`) are recorded, never silently dropped. |
| `request_rate_context` | Optional; rate is computed downstream, not guessed at ingest. |

`ApiFamilies` holds the family constants, and `PRIVILEGE_MUTATION_FAMILIES`
defines which families count as a privilege/credential change.

### `identity.py` — identity resolution

* **IAMUser** → `HUMAN_USER`, baselined on the user ARN.
* **AssumedRole** → baselined on the **role** ARN (so ephemeral sessions roll
  up), while the session ARN is retained in `session_id`.
* **AssumedRole + `webIdFederationData`** (SAML/OIDC/web identity) →
  `FEDERATED_IDENTITY`.
* **AWSService** → `SERVICE_IDENTITY`, keyed `aws-service:<invokedBy>`.
* **ServiceAccount / unknown types** → `MACHINE_IDENTITY`, never mixed with
  human baselines.
* Assumed roles whose session name looks AWS-managed (`AWSServiceRoleFor…`,
  `aws-service-role`) are classified as services, not humans.

An event that cannot be attributed to any principal raises
`IdentityResolutionError` — it is never dropped quietly.

### `session.py` — session construction

Every event belongs to an `IdentitySession`. A single event may look harmless
while a sequence from one context does not:

```
03:12 login → 03:14 AssumeRole → 03:15 IAM policy change → 03:17 CreateAccessKey
```

Session keying prefers the provider's own session identity (assumed-role session
ARN, access key ID) and falls back to a context fingerprint. `SessionTracker`
opens a new session on: identity change, idle gap beyond
`idle_timeout_minutes`, duration beyond `max_duration_hours`, or a context change
(IP / country / user agent, configurable).

### `profile.py` — baseline lifecycle

* `assess_baseline_quality()` grades a baseline `EXCELLENT / GOOD / LIMITED /
  COLD_START` from **real** sample counts, time span and day coverage. A burst of
  5,000 events in one hour is not `EXCELLENT` — it is `COLD_START`.
* `initial_profile()` creates an empty profile that is honest about knowing
  nothing (no invented distributions).
* `ProfileService.select_baseline()` uses the personal baseline when it is
  trustworthy, otherwise falls back to **peers** (same baseline category,
  account, and where available role/team/department). Cold start never means
  "suspicious".
* `BaselineQuality` feeds confidence in Part 2 — weak evidence must lower
  confidence.

Aggregating events into the `normal_*` distributions is `baseline.py` (Part 2).

### `ingestion/aws/cloudtrail.py` — normalization

Accepts three delivery shapes: a raw record, an EventBridge envelope
(`{"detail": …}`), or an S3 file (`{"Records": [...]}`).

`AwsApiClassifier` maps `eventSource` + `eventName` to:

* `service_name` (`iam.amazonaws.com` → `iam`),
* `api_family` (privilege mutation, credential management, STS session, S3
  data read/write, secrets access, KMS crypto, CloudTrail/GuardDuty/Config
  tampering, …),
* `read_or_write` (explicit verbs, direction overrides for crypto APIs, then
  prefix heuristics),
* `event_category` (management / data / signin),
* `privilege_change`.

**Never silently dropped.** `normalize_batch()` quarantines failures with the
raw payload and error context (`strict=True`, the default, raises instead).
Batch size is bounded by `max_records_per_batch`.

### `ingestion/aws/enrichment.py` — the "don't invent data" seam

CloudTrail provides `sourceIPAddress` but **not** country/ASN/geo. The default
`NullIpEnricher` returns "unknown", so location and networking features correctly
see `None` rather than a fabricated anomaly. `StaticIpEnricher` provides
deterministic enrichment for tests and offline evaluation.

### `storage/` — persistence

* `identity_profiles` — one row per identity × baseline window (7/30/90 days).
* `identity_events` — normalized events. **Access keys are stored only as a
  salted SHA-256 fingerprint plus a masked form**; the identifier is not
  recoverable from the database.
* `identity_sessions` — session aggregates.
* `behavioral_features` — per-event feature vectors (Part 2 writes these).
* `security_findings` — the **shared** Aegivion findings table, reused rather
  than duplicated. `FindingRecord` keeps `risk_score` and `confidence` as
  separate fields.
* `baseline_versions` — immutable snapshots; only one active version per
  identity × window.

JSON columns use JSONB on PostgreSQL and JSON elsewhere, so the same models run
under SQLite in tests.

### `config.py` — configuration system

Everything tunable lives here and is settable via `AEGIVION_*` environment
variables. **No score, weight or threshold may be hard-coded anywhere else.**

```
AEGIVION_PRIMARY_WINDOW_DAYS=30
AEGIVION_BASELINE_WINDOWS_DAYS=7,30,90
AEGIVION_MIN_EVENTS_FOR_PERSONAL_BASELINE=50
AEGIVION_BASELINE_FREEZE_RISK_THRESHOLD=70        # poisoning guard
AEGIVION_BASELINE_LIMITED_INFLUENCE_RISK_THRESHOLD=30
AEGIVION_SESSION_IDLE_TIMEOUT_MINUTES=30
AEGIVION_SESSION_MAX_DURATION_HOURS=12
AEGIVION_SESSION_BREAK_ON_CONTEXT_CHANGE=true
AEGIVION_INGEST_STRICT=true
AEGIVION_MAX_RECORDS_PER_BATCH=1000
AEGIVION_QUARANTINE_ON_ERROR=true
AEGIVION_SCORING_WEIGHTS='{"time":0.15,"location":0.20,"ip":0.15,"device":0.10,"api":0.25,"privilege":0.15}'
AEGIVION_SEVERITY_LOW=30
AEGIVION_SEVERITY_MEDIUM=60
AEGIVION_SEVERITY_HIGH=80
AEGIVION_SECRET_SALT=<per-deployment salt>
```

Invalid configuration raises `ConfigurationError` at load time (e.g. a primary
window outside the window set, weights that do not sum to 1.0, severity bands
that do not increase).

---

## 5. Security requirements honoured in Part 1

* Access keys are never logged (`__repr__`, `to_log_dict`), never stored in
  plaintext (salted fingerprint + masked form), and never returned from storage.
* All telemetry passes through typed schemas; unknown fields are rejected.
* Malformed records raise typed errors and are quarantined with their raw
  payload for audit — never silently ignored.
* Detection is read-only with respect to cloud providers.
* Failures are explicit (`NotImplementedYetError` for Part 2 stages) rather than
  fabricated.

---

## 6. Running the tests

From the repository root:

```bash
python -m pip install -r requirements.txt
python -m pytest detection -q
```

The full foundation suite covers schema validation and redaction, the
configuration system, identity resolution, session continuity, CloudTrail
normalization/classification/quarantine, profile quality grading and peer
fallback, and every repository against an in-memory SQLite database.

---

## 7. What Part 2 adds

1. `features.py` — the six behavioral features from real profile distributions.
2. `rules.py` — R001–R012 rule signals (each emits a feature, never a verdict).
3. `baseline.py` — `normal_*` aggregation honouring the poisoning guard: an
   event with risk ≥ `baseline_freeze_risk_threshold` is never folded in.
4. `anomaly.py` — Isolation Forest, trained per baseline category.
5. `scorer.py` + `confidence.py` — risk fusion and confidence calibration.
6. `finding.py` + `detector.py` — structured, explainable findings persisted to
   `security_findings`, ready for ARDE and correlation.
7. A synthetic attack simulator and an evaluation harness (precision, recall,
   F1, false-positive rate, detection latency, lead time).
