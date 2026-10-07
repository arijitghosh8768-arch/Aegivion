# Aegivion Detection Engines

Algorithm #3 — **Cloud Destructive Activity Detector**
(Part 1 foundation + Part 2 behavioral layer + Part 3 anomaly & risk
fusion + Part 4 response orchestration + Part 5 multi-cloud ingestion &
Threat-Correlation integration).

> **This is a DEFENSIVE detection system.** It never performs destructive
> actions: no cloud resources are deleted, no data is encrypted, no snapshots
> or backups are destroyed. All malicious scenarios are represented as
> synthetic or replayed telemetry under
> `detection/cloud_destruction/tests/fixtures/`.

## What is implemented (Parts 1–3 core + Part 4 response + Part 5 integration)

| Deliverable | Status | Where |
|---|---|---|
| Canonical `ResourceActivityEvent` | ✅ | `detection/cloud_destruction/schemas.py` |
| Action taxonomy (13 canonical categories) | ✅ | `detection/cloud_destruction/schemas.py` |
| AWS normalizers (CloudTrail data/control events) | ✅ | `detection/cloud_destruction/normalizer.py` |
| AWS Backup EventBridge ingestion | ✅ | `ingestion/aws/backup_events.py` |
| Snapshot (EBS/RDS) EventBridge ingestion | ✅ | `ingestion/aws/snapshot_events.py` |
| CloudTrail batch ingestor + quarantine | ✅ | `ingestion/aws/cloudtrail_resource_activity.py` |
| `DestructiveActivitySession` builder | ✅ | `detection/cloud_destruction/session.py` |
| `ResourceProtectionProfile` + builder | ✅ | `schemas.py`, `resource_profile.py`, `protection.py` |
| Database models (SQLAlchemy) + repository | ✅ | `detection/cloud_destruction/storage.py` |
| Event provenance + field-availability model | ✅ | `detection/cloud_destruction/provenance.py` |
| Synthetic/replay fixtures (13 scenarios) | ✅ | `tests/fixtures/synthetic/`, `tests/fixtures/replay/` |
| Documentation | ✅ | this file, `docs/ARCHITECTURE.md` |
| **Part 2:** behavior baselines + quality + **poisoning defense** | ✅ | `detection/cloud_destruction/baseline.py` |
| **Part 2:** modification / deletion / version analyzers | ✅ | `modification.py`, `deletion.py`, `versioning.py` |
| **Part 2:** snapshot / backup / recoverability analyzers | ✅ | `snapshot.py`, `backup.py`, `recoverability.py` |
| **Part 2:** protection-degradation analyzer (independent) | ✅ | `protection.py`, `recoverability.py` |
| **Part 2:** rewrite/transform analyzer (content-neutral) | ✅ | `detection/cloud_destruction/rewrite.py` |
| **Part 2:** sequence + temporal analyzers (6 windows) | ✅ | `sequence.py`, `temporal.py` |
| **Part 2:** approved-activity context (auditable/scoped) | ✅ | `detection/cloud_destruction/legitimate.py` |
| **Part 2:** deterministic feature vectors + provenance | ✅ | `detection/cloud_destruction/features.py` |
| **Part 3:** Isolation Forest anomaly model (dependency-free) | ✅ | `detection/cloud_destruction/anomaly.py` |
| **Part 3:** optional supervised slot (XGBoost-if-present) | ✅ | `detection/cloud_destruction/supervised.py` |
| **Part 3:** sequence transition model (history-relative) | ✅ | `detection/cloud_destruction/sequence_model.py` |
| **Part 3:** temporal window engine (9 metrics × 6 windows) | ✅ | `detection/cloud_destruction/temporal_features.py` |
| **Part 3:** risk fusion (versioned, config-weighted) | ✅ | `detection/cloud_destruction/scorer.py` |
| **Part 3:** confidence engine (risk ≠ confidence) | ✅ | `detection/cloud_destruction/confidence.py` |
| **Part 3:** severity policy + versioned findings | ✅ | `detection/cloud_destruction/finding.py` |
| **Part 3:** model/version registry + replay engine | ✅ | `registry.py`, `replay.py` |
| **Part 3:** comparative evaluation framework + comparison run | ✅ | `evaluation.py`, `scripts/run_comparison.py` |
| **Part 4:** versioned response policy + orchestrator | ✅ | `detection/cloud_destruction/response.py` |
| **Part 5:** Azure Activity Log normalizer/ingestor | ✅ | `ingestion/azure/activity_log.py` |
| **Part 5:** GCP Cloud Audit Log normalizer/ingestor | ✅ | `ingestion/gcp/audit_log.py` |
| **Part 5:** Threat-Correlation broker (one-way seam) | ✅ | `correlation/threat_correlation.py` |
| Unit + end-to-end + boundary tests (384) | ✅ | `detection/cloud_destruction/tests/` |

## What is deliberately NOT implemented yet

No future part is stubbed inside this package anymore: Parts 1–5 are
implemented. Remaining work lives in later parts (new cloud providers,
new correlation feeds) and lands as new modules, not placeholders.

## Part 3 rules (enforced + tested)

1. **ML must earn its place.** The comparative evaluation
   (`python scripts/run_comparison.py`) measures rules-only vs +baseline vs
   +sequence vs +ML vs full detector on precision/recall/F1/PR-AUC/FPR/
   latency. On the synthetic corpus, baselines remove the false positives
   (F1 0.185 → 1.000) and ML preserves the operating point at a measured
   latency cost.
2. **Risk ≠ confidence.** Risk = how dangerous the behavior appears;
   confidence = how strong and complete the evidence is (feature
   availability, telemetry completeness, baseline quality, model/rule
   agreement). Confidence is never `risk / 100`.
3. **Severity is a policy, not a count.** LOW/MEDIUM/HIGH/CRITICAL derive
   from risk × confidence × criticality × recoverability × evidence quality
   (versioned `SeverityPolicy`); CRITICAL requires evidence, not volume.
4. **No fabricated labels.** The supervised slot trains only on declared or
   explicitly-synthetic labels; synthetic benchmark results are stamped
   `label_source="synthetic"` and are never presented as production
   performance. Brier/ECE are reported, not assumed.
5. **Everything is versioned and reproducible.** Findings carry model,
   feature, baseline, scoring, rule, confidence and severity versions;
   replaying the same events + config + versions reproduces the same
   scored result (digest-verified).

## Part 2 behavioral rules (enforced + tested)

1. **Volume is never a verdict.** "Many deletes" is not automatically
   malicious; every deviation is relative to the *actor's own trusted
   baseline*, with raw counters attached for audit.
2. **Deviation semantics.** All `*_deviation` / `*_anomaly` features map to
   `[0, 1]`: `0.0` at/below normal, `1.0` at/above the configured factor,
   `None` when no baseline evidence exists — never silently zero.
3. **Baseline poisoning defense.** Historical sessions are classified LOW /
   MEDIUM / HIGH / CRITICAL from evidence counters; HIGH/CRITICAL never
   teach the baseline, MEDIUM has limited influence (approval via an
   auditable profile restores full weight only at LOW/MEDIUM). Baselines
   are versioned; prior generations are retained for audit.
4. **Protection degradation is independent** from actual data destruction:
   posture changes and delete volume are separate features.
5. **Recoverability is protection-state math**: mass deletion + intact
   protected backups reads differently from mass deletion + version/backup
   scrubbing.
6. **Transform ≠ encryption.** The rewrite feature is
   `rewrite_transform_score` — content-neutral evidence. Claiming data is
   encrypted requires content-level proof this detector does not have.
7. **Legitimate activity is explicit context**, not a whitelist: profiles
   are auditable (id, version, justification), scoped (actor / resource /
   operation / time window), reversible (disable anytime) and time-aware
   (UTC windows + expiry).

## Design rules enforced (Part 1, unchanged)

| Deliverable | Status | Where |
|---|---|---|
| Canonical `ResourceActivityEvent` | ✅ | `detection/cloud_destruction/schemas.py` |
| Action taxonomy (13 canonical categories) | ✅ | `detection/cloud_destruction/schemas.py` |
| AWS normalizers (CloudTrail data/control events) | ✅ | `detection/cloud_destruction/normalizer.py` |
| AWS Backup EventBridge ingestion | ✅ | `ingestion/aws/backup_events.py` |
| Snapshot (EBS/RDS) EventBridge ingestion | ✅ | `ingestion/aws/snapshot_events.py` |
| CloudTrail batch ingestor + quarantine | ✅ | `ingestion/aws/cloudtrail_resource_activity.py` |
| `DestructiveActivitySession` builder | ✅ | `detection/cloud_destruction/session.py` |
| `ResourceProtectionProfile` + builder | ✅ | `schemas.py`, `resource_profile.py`, `protection.py` |
| Database models (SQLAlchemy) + repository | ✅ | `detection/cloud_destruction/storage.py` |
| Event provenance + field-availability model | ✅ | `detection/cloud_destruction/provenance.py` |
| Synthetic/replay fixtures (13 scenarios) | ✅ | `tests/fixtures/synthetic/`, `tests/fixtures/replay/` |
| Unit + end-to-end + boundary tests (181) | ✅ | `detection/cloud_destruction/tests/` |
| Documentation | ✅ | this file, `docs/ARCHITECTURE.md` |

## Deliberately absent

No stubs: every Part 2/3 module listed above is implemented and tested.
What remains out of scope by design:

- **Production ML labels.** The supervised slot trains only on declared or
  explicitly-synthetic labels; benchmark numbers are stamped
  `label_source="synthetic"`.
- **Destructive actions.** The detector and the response orchestrator plan
  and log; enforcement actions require explicit approval wiring and are
  never performed by this codebase.
- **Cross-algorithm coupling.** Algorithm #3 imports nothing from #1/#2;
  the only seam is the one-way Threat-Correlation broker (`correlation/`).

## Design rules enforced

1. **Never invent values.** Any field telemetry does not provide stays `None`
   and the event's `feature_availability` records *why* (`not_in_source`,
   `not_applicable`, `parse_failure`, `redacted`, `enrichment_missing`, ...).
2. **Raw actions are evidence.** `raw_action` keeps the provider-specific
   event name (`s3:DeleteObjectVersion`) next to the canonical
   `action_category` (`version_delete`).
3. **Protection state comes only from a catalog.** The normalizer never
   guesses versioning/backup state; without a catalog entry the fields stay
   `None` + `enrichment_missing`.
4. **Telemetry is never silently dropped.** Malformed records raise (strict)
   or are quarantined with the raw payload (lenient). Out-of-scope-but-valid
   records are *skipped*, not counted as malformed.
5. **No cross-algorithm coupling.** See "Strict independence" below.

## Strict independence

This detector operates independently of Algorithm #1 (Credential Compromise)
and Algorithm #2 (Data Exfiltration): no imports, no calls, no shared state,
no use of their scores, findings or models. The interaction with the rest of
Aegivion runs through Aegivion Threat Correlation (`correlation/`), a
one-way, dependency-free seam: findings flow in via `ThreatCorrelationBroker`,
are captured immutably, and can only be annotated with additive correlation
context. The correlation package imports nothing from `detection.*`
or `ingestion.*`.

`tests/test_independence.py` enforces this mechanically: static import scan,
source-text scan, and a runtime `sys.modules` isolation check.

## Running

```bash
pip install -e ".[dev]"
python scripts/generate_fixtures.py     # regenerate the 13 fixture scenarios
python -m pytest detection/cloud_destruction/tests -q
```

Configuration is environment-driven (`AEGIVION_DESTRUCTION_*` prefix), e.g.:

```bash
AEGIVION_DESTRUCTION_SESSION_IDLE_TIMEOUT_MINUTES=30
AEGIVION_DESTRUCTION_INGEST_STRICT=true
AEGIVION_DESTRUCTION_STORAGE_URL=sqlite:///destruction.db
AEGIVION_DESTRUCTION_BASELINE_MIN_SESSIONS_GOOD=20
AEGIVION_DESTRUCTION_POISONING_HIGH_RECOVERY_IMPAIRING=3
AEGIVION_DESTRUCTION_BEHAVIORAL_BURST_WINDOW_MINUTES=5
```

Part 1/2 configuration intentionally contains **no scoring thresholds** —
score fusion arrives with Part 3.

## Canonical action taxonomy

`create`, `read`, `modify`, `rewrite`, `delete`, `version_delete`,
`snapshot_delete`, `backup_delete`, `recovery_point_delete`,
`protection_change`, `restore`, `share_change`, `policy_change` — plus
operation nuance (`single`, `batch`, `versioned`, `delete_marker`,
`recovery_impairing`).

## Provider scope

AWS (CloudTrail data/control events, S3 object/version activity, EBS +
RDS snapshots, AWS Backup, EventBridge service events), Azure (Activity Log
management plane) and GCP (Cloud Audit Logs: Admin Activity + Data Access).
All internal schemas are provider-neutral, so adding a provider means a new
normalizer module, not a new algorithm.
