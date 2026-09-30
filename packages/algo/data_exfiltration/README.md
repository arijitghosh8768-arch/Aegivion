# Aegivion Detection Engines

Algorithm #2 — **Cloud Data Exfiltration Detector** (Part 1 foundation + Part 2 behavioral intelligence + Part 3 ML & risk fusion + Part 4 ARDE validation & explainability + Part 5 final-stage evaluation & serving).

## What is implemented (Part 1)

| Deliverable | Status | Where |
|---|---|---|
| Provider-neutral data schema | ✅ | `detection/data_exfiltration/schemas.py` |
| AWS normalizers (CloudTrail data events, VPC Flow Logs) | ✅ | `detection/data_exfiltration/normalizer.py`, `ingestion/aws/` |
| Data-access session builder | ✅ | `detection/data_exfiltration/session.py` |
| VPC flow → session correlation | ✅ | `detection/data_exfiltration/correlate.py` |
| Resource profile model | ✅ | `detection/data_exfiltration/resource_profile.py` |
| Behavioral baseline (descriptive, versioned) | ✅ | `detection/data_exfiltration/baseline.py` |
| Database models (events/sessions/profiles/baselines/findings) | ✅ | `detection/data_exfiltration/storage.py` |
| Provenance handling | ✅ | `detection/data_exfiltration/measurement.py`, `raw_store.py` |
| Macie / geo enrichment interfaces | ✅ | `detection/data_exfiltration/enrichment.py` |
| Feature extraction (deterministic, documented) | ✅ | `detection/data_exfiltration/features.py` |
| Analysis modules (volume/destination/access/sensitivity) | ✅ | `volume.py`, `destination.py`, `access_pattern.py`, `sensitivity.py` |
| Discovery findings + ARDE payload | ✅ | `detection/data_exfiltration/finding.py` |
| Raw telemetry persistence (redaction + digest verify) | ✅ | `detection/data_exfiltration/raw_store.py` |
| Test fixtures (10 scenarios + gaps + missing-field corpus) | ✅ | `detection/data_exfiltration/tests/fixtures/` |
| Documentation (this file + architecture) | ✅ | `README.md`, `docs/ARCHITECTURE.md` |

## Part 2 — behavioral intelligence layer

Eight independent signal dimensions (all structured features, **no risk
verdicts yet** — fusion is Part 3):

| Dimension | Module | Highlights |
|---|---|---|
| Volume intelligence | `intelligence/volume_intelligence.py` | 5m/15m/1h/6h/24h/7d windows; bytes/objects/requests/diversity deviations; median+MAD, never mean±std only |
| Destination intelligence | `intelligence/destination_intelligence.py` | destination/ASN/country/provider novelty; TRUSTED_INTERNAL / KNOWN_BUSINESS / KNOWN_CLOUD / UNKNOWN_EXTERNAL / HIGH_RISK_EXTERNAL |
| Access-pattern intelligence | `intelligence/access_pattern_intelligence.py` | resource/prefix/category novelty, diversity, spread; one→many objects, one bucket→many sensitive prefixes, rapid multi-resource patterns |
| Sequence analysis | `intelligence/sequence.py` | n-gram deviation from the actor's historical action sequences — no attack signatures |
| Sensitivity | `intelligence/sensitivity_intelligence.py` | Macie / tags / Aegivion / manual sources; `data_sensitivity` kept separate from `business_criticality` |
| Time intelligence | `intelligence/time_intelligence.py` | circular hour distance, weekday novelty, approved schedules (scheduled 02:00 backup ≠ anomalous 02:00 access) |
| Actor-resource relationship | `intelligence/actor_resource_intelligence.py` | actor→resource and workload→resource novelty, cross-business-unit access |
| Network egress | `intelligence/egress_intelligence.py` | egress/external-egress ratios only where telemetry is comparable; otherwise explicitly unavailable |

Supporting machinery: `stats.py` (robust statistics), `windows.py`
(windowed aggregation), `intelligence/baseline_engine.py` (actor /
resource / workload / destination scopes, 7/30/90-day lookbacks, peer
groups, cold start, versioned snapshots), `intelligence/baseline_guard.py`
(poisoning protection), `intelligence/feature_set.py`
(`BehavioralFeatureSet` with per-feature availability + provenance),
`intelligence/profiler.py` (assembly).

### Core principles enforced in Part 2

- **Large volume is never automatically malicious** — every dimension is
  independent; personas prove big-but-routine transfers stay quiet on
  destination/time/relationship dimensions.
- **Absence of history is not suspicious** — cold start returns
  unavailable/0.0 and may fall back to peer baselines, never to guilt.
- **Novel ≠ malicious** — new destinations/resources are evidence with
  classifications, not verdicts.
- **Baseline poisoning protection** — LOW risk updates trusted baselines,
  MEDIUM is audit-only, HIGH never shapes them automatically
  (`BaselinePoisoningPolicy`, `BaselineInfluence`).
- **One-sided deviations** — volume-style metrics only flag "unusually
  large"; being below typical is never a finding.

| Deliverable (Part 2) | Status | Where |
|---|---|---|
| Volume analyzer | ✅ | `intelligence/volume_intelligence.py` |
| Destination analyzer | ✅ | `intelligence/destination_intelligence.py` |
| Access-pattern analyzer | ✅ | `intelligence/access_pattern_intelligence.py` |
| Sequence analyzer | ✅ | `intelligence/sequence.py` |
| Sensitivity analyzer | ✅ | `intelligence/sensitivity_intelligence.py` |
| Time analyzer | ✅ | `intelligence/time_intelligence.py` |
| Actor-resource baseline | ✅ | `intelligence/actor_resource_intelligence.py` |
| Network egress analyzer | ✅ | `intelligence/egress_intelligence.py` |
| Baseline engine | ✅ | `intelligence/baseline_engine.py` |
| Baseline poisoning protection | ✅ | `intelligence/baseline_guard.py` |
| Comprehensive unit tests + 10 personas | ✅ | `tests/` |

## Part 3 — ML + risk fusion layer

`detection/data_exfiltration/ml/` — everything consumes Part 2 features
and produces risk, confidence, and severity. ML must **earn** its place:
the harness measures it.

| Deliverable | Status | Where |
|---|---|---|
| Feature pipeline (frozen order, availability mask) | ✅ | `ml/feature_vector.py` |
| Temporal rolling features (5m–24h, burst/slow) | ✅ | `ml/temporal.py` |
| Isolation Forest (deterministic, seeded, ECDF-normalized) | ✅ | `ml/isolation_forest.py` |
| Optional supervised model (strictly gated, never fabricates labels) | ✅ | `ml/supervised.py` |
| Risk fusion (interpretable, config-driven, versioned weights) | ✅ | `ml/fusion.py` |
| Confidence engine (risk ≠ confidence; Platt + Brier/ECE; explicit states) | ✅ | `ml/confidence_engine.py` |
| Severity (risk + confidence + sensitivity + evidence) | ✅ | `ml/severity.py` |
| Model versioning on every finding | ✅ | `ml/versioning.py`, `finding.py` |
| Temporal splits / replay mode (no leakage) | ✅ | `ml/replay.py` |
| Comparative evaluation A/B/C/D + 5 artifacts | ✅ | `ml/evaluation.py`, `scripts/generate_evaluation.py` |
| Full test suite (222 passing) | ✅ | `tests/` |

### Measured result on the synthetic fixture (marked synthetic everywhere)

| Variant | Components | Precision | Recall | F1 | PR-AUC | FPR |
|---|---|---|---|---|---|---|
| A | rules only | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| B | rules + baseline fusion | 1.00 | 0.79 | 0.88 | 1.00 | 0.00 |
| C | B + Isolation Forest | 1.00 | 0.91 | 0.95 | 1.00 | 0.00 |
| D | C + gated supervised | 1.00 | 0.91 | 0.95 | 1.00 | 0.00 |

Read honestly: on THIS fixture, plain rules (A) already separate the
synthetic classes; weighted fusion (B) dilutes subtle attacks below the
threshold; the Isolation Forest (C) measurably recovers recall — ML earns
its place here; D equals C because there is genuinely no labeled data to
train the supervised component on (the gate refuses to pretend).
These numbers describe the fixture, not real-world performance.

Artifacts (deterministic, seed 42): `evaluation_artifacts/metrics.json`,
`precision_recall.json`, `roc_data.json`, `calibration.json`,
`ablation_base.json`. Regenerate with
`.venv/Scripts/python scripts/generate_evaluation.py` — a regression test
asserts the committed artifacts match a fresh run.

### Part 3 principles enforced

- **Risk is not confidence** — separate engines, separate fields; findings
  carry both plus an explicit confidence state (`calibrated` /
  `heuristic` / `insufficient_data`). No labeled data ⇒ no fake
  probabilities.
- **No data leakage** — strict chronological train/validation/test; the IF
  trains only on the training period; test sessions scored once.
- **Determinism** — fixed seeds, frozen feature order, index-arithmetic
  fixtures (never salted `hash()`); replay runs are bit-identical.
- **Versioned everything** — weights content-versioned; every finding
  carries model_name/model_version/feature_version/baseline_version/
  scoring_version/variant.
- **Severity is multi-input** — thin evidence caps loud risk; sensitivity
  promotes only corroborated risk.

## Part 4 — ARDE validation + explainability

`detection/data_exfiltration/arde/` — the release gate that challenges a
candidate finding *before* it is emitted. ARDE never silences a finding:
it changes the status and records why.

| Deliverable | Status | Where |
|---|---|---|
| Validation outcome (PASSED / PASSED_WITH_WARNINGS / REVIEW_REQUIRED / REJECTED) | ✅ | `arde/validator.py`, `arde/models.py` |
| Ten consistency checks (evidence completeness, internal consistency, model-reaction, ...) | ✅ | `arde/consistency.py` |
| Approved-activity registry (scoped, reversible, time-aware) | ✅ | `arde/approved_activities.py` |
| Robustness scoring (ROBUST / MODERATE / FRAGILE) | ✅ | `arde/robustness.py` |
| Machine-readable + analyst-readable explanation | ✅ | `arde/explain.py`, `arde/formatter.py` |
| Hash-chained audit log | ✅ | `arde/audit.py` |
| Adversarial robustness (9 scenarios) | ✅ | `arde/robustness.py`, `tests/test_arde_robustness.py` |
| Detector integration with downgrade-only severity | ✅ | `arde/integration.py`, `detector.py` |

Guarantees: ARDE can only ever *lower* severity; it records every exception
it considered (matched or not); and its checks **abstain** — never pass —
when telemetry is missing. With no ARDE components wired, Part 1/2/3
behavior is unchanged (test-guarded).

## Part 5 — final-stage evaluation, output contract & serving

| Deliverable | Status | Where |
|---|---|---|
| A–E comparative evaluation over 15 scenario families | ✅ | `evaluation/scenarios.py`, `evaluation/variants.py` |
| Ablation (volume/destination/sensitivity/access/time/egress/ML/ARDE) | ✅ | `evaluation/ablation.py` |
| Threshold tuning on validation only + split-integrity proof | ✅ | `evaluation/tuning.py` |
| Error analysis (structured FP/FN records) | ✅ | `evaluation/error_analysis.py` |
| Performance measurement (batch + streaming) | ✅ | `evaluation/performance.py` |
| Stable output contract on every finding | ✅ | `output_contract.py`, `finding.py` |
| Dashboard view model | ✅ | `dashboard.py` |
| Five REST endpoints (framework-neutral + WSGI) | ✅ | `api/` |
| Mandatory independence + 17-step acceptance tests | ✅ | `tests/test_final_*.py` |

### Measured result on the synthetic 15-family fixture (seed 42, marked synthetic)

| Variant | Components | Precision | Recall | F1 | PR-AUC | FPR |
|---|---|---|---|---|---|---|
| A | rules only | 0.82 | 0.88 | 0.85 | 0.81 | 0.43 |
| B | + baseline fusion | 0.80 | 0.50 | 0.62 | 0.92 | 0.29 |
| C | + Isolation Forest | 0.80 | 0.50 | 0.62 | 0.91 | 0.29 |
| D | + gated supervised | 0.80 | 0.50 | 0.62 | 0.91 | 0.29 |
| E | D + ARDE | 0.80 | 0.50 | 0.62 | 0.91 | 0.29 |

The chronological test period covers all 15 families (at least one instance
each). E precision@high-risk = 1.00; recall@fixed-FPR = 0.50. ARDE reviewed
variant E's alerts and marked 10 for review (0 rejected).

Threshold tuning selected **0.37 on the validation period** and lifted test
recall from 0.50 (at the 0.5 default) to 1.00 on the test sample, at the cost
of 3 false positives. That 1.00 is a **small-sample artifact** (16 positive,
7 negative test sessions) and is explicitly labelled so in
`final_threshold_tuning.json` — it is not a claim of perfect detection. The
test period was scored once and never consulted during selection.

Ablation (leave-one-component-out, test period): access-pattern removal
costs the most ranking quality (ΔPR-AUC −0.13); the ML component earns a
small but real PR-AUC gain (ΔPR-AUC +0.014) — it is genuinely fitted and
scored, not a label. Removing **volume** (ΔF1 +0.29, ΔFPR −0.14) or **time**
(ΔF1 +0.10) *improves* the headline numbers on this fixture — the honest
signal that these dimensions contribute more false positives than true
positives at the default threshold here ("large is not malicious").
Destination, sensitivity and ARDE deltas are 0.0 on this fixture.

Read honestly: these numbers describe a synthetic fixture and nothing more;
no variant reaches perfect detection at the default operating point.

Artifacts (deterministic except the performance file; seed 42):
`evaluation_artifacts/final_metrics.json`, `final_ablation.json`,
`final_error_analysis.json`, `final_arde_impact.json`,
`final_threshold_tuning.json`, plus the machine-dependent
`final_performance.json`. Regenerate with
`.venv/Scripts/python scripts/generate_final_evaluation.py`.

### Output contract

Every released finding carries `metadata["output_contract"]`
(`output_contract.py`) with a fixed key set: `finding_type`, `severity`,
`risk_score`, `confidence`, `robustness_score`, `actor`, `resource`,
`session`, `data_volume`, `sensitivity`, `destination`, `temporal_context`,
`signals`, `supporting_evidence`, `contradicting_evidence`,
`baseline_quality`, `feature_availability`, `model_version`,
`feature_version`, `baseline_version`, `scoring_version`, `rule_version`,
and `recommended_next_steps` (investigation steps only — this engine is
read-only).

### REST endpoints

```
POST /api/v1/detections/data-exfiltration/analyze
GET  /api/v1/detections/data-exfiltration/findings
GET  /api/v1/data-resources/{resource_id}/profile
GET  /api/v1/data-sessions/{session_id}
GET  /api/v1/findings/{finding_id}/explanation
```

Handlers are framework-neutral (`api/service.py`), wired by
`api/router.py`, and exposed through a stdlib WSGI app (`api.create_app`)
— no extra dependencies. All endpoints are read-only.

## What is deliberately NOT implemented

| Item | Status | Where the contract lives |
|---|---|---|
| XGBoost | ❌ optional at deployment; dependency-free logistic trainer ships behind the same gate | `ml/supervised.py` |
| Isotonic calibration | ❌ Platt scaling ships; isotonic is a drop-in addition | `ml/confidence_engine.py` |
| Real-world weight tuning | ❌ defaults are the working hypothesis, explicitly not "optimal" | `ml/fusion.py` |

There are no hardcoded risk values anywhere in this codebase. Analysis
modules produce **evidence signals only** (`risk_score` stays `None`), and
findings are `DATA_DISCOVERY` records with **no severity, no confidence,
no risk score** until Part 2 exists.

## Independence from Algorithm #1

This detector does not import, call, or reference the Credential
Compromise Detector. A regression test
(`test_finding_stubs.py::TestDetectorIndependence`) scans the package
source for forbidden identifiers (`credential_compromise`,
`identity_compromise`) and fails the build if any appear.

Part 5 adds explicit independence tests
(`tests/test_final_independence.py`): Algorithm #2 runs with Algorithm #1
OFF; a HIGH credential-compromise signal (an inert stub) never manufactures
a data-exfiltration finding when the data behaviour is normal; the finding
output is byte-identical with and without the sibling engine present; and a
HIGH data-exfiltration result asserts nothing about credentials or identity.
The only sanctioned meeting point between the two algorithms is Aegivion
Threat Correlation, downstream of the findings emitted here.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"      # Windows; on POSIX: .venv/bin/pip
.venv/Scripts/pytest detection/data_exfiltration/tests
```

Minimal pipeline usage:

```python
from detection.data_exfiltration.config import DetectorConfig
from detection.data_exfiltration.detector import DataExfiltrationDetector
from detection.data_exfiltration.raw_store import RawEventStore
from detection.data_exfiltration.storage import DetectionRepository
from ingestion.aws.cloudtrail_data_events import read_cloudtrail_data_events
from ingestion.aws.vpc_flow_logs import read_vpc_flow_logs

detector = DataExfiltrationDetector(
    config=DetectorConfig(),
    raw_store=RawEventStore("raw_events/"),
    repository=DetectionRepository("sqlite:///aegivion.db"),
)
result = detector.process_events(
    cloudtrail_records=list(read_cloudtrail_data_events("cloudtrail.jsonl")),
    vpc_flow_records=list(read_vpc_flow_logs("flow.log")),
)
print(result.stats.as_dict())
for finding in result.findings:
    print(finding.finding_id, finding.title)
```

## Data honesty rules

1. **Never invent.** Missing fields stay `None` with explicit
   `unavailable` markers — never zeros, never guesses.
2. **Explicit presence vocabulary**: `available` / `observed` /
   `estimated` / `unavailable` (`ValuePresence`).
3. **Provenance on every measurement**: source + confidence
   (`MeasurementSource`, `MeasurementConfidence`) and a machine-readable
   `provenance()` record.
4. **No silent cross-source merging**: bytes from CloudTrail (estimated)
   and VPC flow logs (observed) are aggregated as *separate categories*
   inside `MultiSourceMeasurement`; conflicts are flagged, not averaged.
5. **Raw events are never discarded**: every normalized event can carry a
   `raw_event_reference` into the raw store, which redacts credential
   material and supports digest verification.
6. **Sensitivity is external**: only Macie (or another enrichment source)
   can set it; the engine never classifies content.
7. **Geography is never guessed from IPs**: geo context arrives only via
   an explicitly injected `GeoEnricher`; unknown lookups stay unknown.

## Known capability gaps (documented, not hidden)

See `detection/data_exfiltration/tests/fixtures/gaps.py` — each record is
a fixture proving the gap is handled honestly:

- GAP-01: AWS account aliases are not resolved.
- GAP-02: resource ARNs are not reconstructed for all services (S3 uses
  `s3://bucket`; DynamoDB builds its ARN from request parameters).
- GAP-03: `owner` / `business_unit` are not auto-populated (supply an
  owner registry to `ResourceProfileBuilder`).
- GAP-04: missing `awsRegion` stays unavailable (no partition guessing).

Correlation limitation: without ENI/principal identity mapping, VPC flows
are linked to sessions by time window + IP evidence, with a documented
fallback for in-VPC traffic. Correlation only ever *adds* observed
network evidence; it cannot raise risk by itself.

## Azure / GCP readiness

Every schema is provider-neutral (`Provider` enum already reserves
`azure` / `gcp`). Adding a cloud means adding a normalizer method on
`EventNormalizer` plus ingestion readers — no schema changes.

## Layout

```
detection/data_exfiltration/
    schemas.py          canonical models (event, session, profile, finding)
    measurement.py      provenance-carrying measurement primitives
    normalizer.py       CloudTrail / VPC flow / generic normalizers
    session.py          DataAccessSession builder (gap-based windows)
    correlate.py        flow -> session correlation + evidence merge
    resource_profile.py per-resource observed history
    baseline.py         versioned descriptive baselines
    features.py         deterministic, documented session features
    volume.py           volume analysis (signals only)
    destination.py      destination analysis (signals only)
    access_pattern.py   access-pattern analysis (signals only)
    sensitivity.py      sensitivity surface (signals only)
    anomaly.py          ML interface + not-implemented stub
    scorer.py           risk-fusion interface + not-implemented stub
    confidence.py       calibration interface + not-implemented stub
    finding.py          discovery findings + ARDE payload
    detector.py         pipeline orchestration
    storage.py          SQLAlchemy models + repository
    raw_store.py        raw event persistence (redaction + verify)
    enrichment.py       Macie / geo interfaces
    config.py           tuning knobs (no risk logic)
    exceptions.py       exception hierarchy
    output_contract.py  stable finding output contract
    dashboard.py        dashboard view model (analyst panels)
    arde/               Part 4: validation, checks, exceptions, explain, audit
    evaluation/         Part 5: scenarios, variants, ablation, tuning, errors,
                        performance, runner (A-E comparison over 15 families)
    api/                Part 5: REST handlers + router + WSGI app
    tests/              356 tests incl. ARDE, independence, 17-step acceptance

ingestion/aws/
    cloudtrail_data_events.py   JSONL / Records[] readers
    vpc_flow_logs.py            v2/v3 text + JSON readers
    macie.py                    findings reader
```
