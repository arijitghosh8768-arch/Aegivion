# Algorithm #2 Architecture — Cloud Data Exfiltration Detector

## Pipeline

```
Cloud Telemetry (CloudTrail data events, VPC Flow Logs, Macie)
        |
        v
Ingestion readers            ingestion/aws/*          (files -> dicts, malformed kept)
        |
        v
Event Normalization          normalizer.py            (provider -> DataActivityEvent)
        |                                                 skip UnsupportedEventError,
        |                                                 collect MalformedEventError
        v
Data Activity Model          schemas.py               (canonical, provenance-carrying)
        |
        v
Session Construction         session.py               (per-actor inactivity-gap windows)
        |
        v
Flow Correlation             correlate.py             (adds observed network evidence)
        |
        v
Resource Profile             resource_profile.py      (observed actors/hours/volumes)
        |
        v
Behavioral Baseline          baseline.py              (descriptive p50/p95, versioned)
        |
        v
Feature Extraction           features.py              (deterministic + documented)
        |
        v
Behavioral Intelligence      intelligence/profiler.py (Part 2 - features ONLY,
        |                                             8 dimensions + baselines)
        v
Analysis Modules             volume / destination / access_pattern / sensitivity
        |                                             (evidence signals ONLY)
        v
Feature Vector               ml/feature_vector.py     (frozen order + mask)
        |
        v
Risk Fusion                  ml/fusion.py             (Part 3 - weighted, versioned)
        |                                     + ml/rules.py, ml/isolation_forest.py
        v
Confidence Engine            ml/confidence_engine.py  (separate from risk;
        |                                     calibrated | heuristic | insufficient)
        v
Severity Mapping             ml/severity.py           (risk+confidence+
        |                                             sensitivity+evidence)
        v
Security Finding             finding.py               (ARDE + model identity)
        |
        v
Persistence                  storage.py + raw_store.py
        |
        v
Threat Correlation           (downstream consumer; the only meeting point
                              with Algorithm #1)
```

## Module contracts

### DataActivityEvent (schemas.py)
Canonical provider-neutral record. Fields not provided by the source stay
`None` and are mirrored by `*_availability` (provenance grade) and
`*_presence` (available/observed/estimated/unavailable) slots. Numeric
measurements are `MultiSourceMeasurement` objects. A normalizer raises
`UnsupportedEventError` for structurally-valid non-data events (skipped)
and `MalformedEventError` for unnormalizable records (collected, never
silently dropped).

### Measurement (measurement.py)
`SourceMeasurement(value, source, confidence)` is the atomic unit.
`MultiSourceMeasurement` keeps per-source contributions side by side,
returns the max as the primary value (conservative for volume metrics),
flags conflicts beyond a relative tolerance, and derives `presence` from
the best confidence. Session/profile aggregation sums **per
(source, confidence) category** — observed and estimated bytes are never
merged into one number.

### DataAccessSession (session.py)
Per-actor activity burst approximated by inactivity-gap windows
(`inactivity_gap`, `max_session_duration` caps). Aggregates are explicit
sums over contributing events; empty categories stay zero/absent, never
fabricated. Flush semantics: `flush()` returns every session built since
the previous flush.

### Correlation (correlate.py)
Three-tier conservative matching: time window; IP link against session
destinations; documented fallback for in-VPC traffic when the session has
no destination context. Merging **adds** evidence (observed flow bytes,
destinations) — it never overwrites data-event measurements and cannot
raise risk on its own.

### Baseline (baseline.py)
Immutable, versioned descriptive snapshot: p50/p95 of duration, bytes,
egress, event/request counts, destination diversity, sensitive-session
share. No thresholds, no anomaly verdicts — deciding "abnormal" belongs
to Part 2 fusion.

### Findings (finding.py)
`DATA_DISCOVERY` records with full ARDE payload (`arde_version 1.0`):
session block, resources, volumes (with per-measurement provenance and
explicit unavailability reasons), network, sensitivity, raw event
references, and embedded analysis signals. Severity/confidence/risk stay
`None` until the Part 2 interfaces have real implementations.

## Part 2 — behavioral intelligence layer

Sits between feature extraction and risk fusion. Produces a
`BehavioralFeatureSet` per session; never a verdict.

```
                     +---------------------+
  sessions, events ->| BehavioralProfiler  |<--- IntelligenceContext
                     +---------------------+      (known universes, registries,
                       |  |  |  |  |  |  |        schedules, peer group)
       volume -+------+  |  |  |  |  |  +--- egress
   destination +----------+  |  |  |  +------ actor-resource
 access-pattern +------------+  |  +--------- sensitivity
      sequence +---------------+------------ time
                     all 8 -> BehavioralFeatureSet
                     (value + availability + provenance per feature)
```

Key contracts:

- **BaselineEngine** (`baseline_engine.py`): raw-observation store per
  (scope, metric, entity) with scopes actor/resource/workload/destination
  and 7/30/90-day lookbacks (half-open windows). Robust stats only:
  median, percentiles, MAD, modified z-scores (Iglewicz–Hoaglin gate 3.5).
  Personal -> peer fallback (excluding self) -> none. `versioned_snapshot`
  exports a content-addressed baseline version.
- **Poisoning protection** (`baseline_guard.py`): observations carry
  `BaselineInfluence`. ELIGIBLE shapes trusted stats; LIMITED/BLOCKED are
  audit-only. Unknown risk labels default to LIMITED (conservative).
- **Cold start**: <= 4 trusted observations => cold_start; peer-group
  statistics (self-excluded) are the fallback; "no history" yields
  score None, never suspicion.
- **One-sided deviation**: volume-style metrics flag only "unusually
  large". Below-typical activity is never a finding.
- **Sequence analysis**: bigram deviation vs the actor's historical
  action n-grams; no signatures, cold start safe.
- **Sensitivity vs criticality**: `data_sensitivity` (Macie/tags/registry)
  is stored and reported strictly separately from
  `business_criticality` (asset registry); Macie never implies criticality.
- **Egress ratios**: computed only when both halves exist; observed+observed
  -> observed, any estimated half -> estimated, missing -> unavailable.

Feature availability vocabulary (per feature):
`observed` (warm history / real telemetry), `estimated` (peer/cold-start
fallback or estimated input), `unavailable` (no fabrication).

## Part 3 — ML + risk fusion

```
BehavioralFeatureSet ──> build_feature_vector ──> MLFeatureVector (frozen order,
                                     |                            availability mask)
                                     v
        +----------------------------+----------------------------+
        |                |                       |                 |
     RulePolicy    WeightedFusionEngine   IsolationForest   SupervisedModel
     (transparent)  (versioned weights,    (seeded, ECDF-    (gated: labeled
                    renormalized)           normalized)       data only)
        +----------------------------+----------------------------+
                                     v
                          risk_score (0..1)          ≠     confidence_score
                          FusionResult                     ConfidenceAssessment
                                     v
                          severity_from(risk, confidence,
                                        sensitivity, evidence_quality)
                                     v
                     ScoredSession + ModelVersionInfo -> finding
```

Contract highlights:

- **Fusion renormalizes**: unavailable features are excluded and weights
  re-share over available components; ``contributions`` shows the exact
  basis of every score. Weight vectors are content-versioned (`fw-…`).
- **Isolation Forest**: pure-python, seeded (default 42), fixed feature
  order; raw isolation coefficient converted to 0..1 via ECDF over the
  training scores — never a fabricated 1.0; refuses to score before fit.
- **Confidence states**: ``calibrated`` (Platt on labeled data, Brier/ECE
  reported), ``heuristic`` (explicitly not a probability),
  ``insufficient_data`` (no claim at all). Availability, baseline quality,
  source reliability, model agreement, and evidence consistency feed it.
- **Severity**: no single number decides; thin evidence caps CRITICAL to
  MEDIUM; low confidence caps to HIGH; sensitivity promotes only when
  risk >= 0.6.
- **Replay**: chronological train/validation/test (default 60/20/20); IF
  fits on train rows only; < 10 usable rows ⇒ no ML component rather than
  a pretend model.
- **Evaluation artifacts** (deterministic, synthetic-marked):
  `metrics.json`, `precision_recall.json`, `roc_data.json`,
  `calibration.json`, `ablation_base.json`. Regeneration script:
  `scripts/generate_evaluation.py`; a test asserts the committed
  artifacts match a fresh run.

## Part 4 — ARDE validation + explainability

Sits between scoring and release. Every candidate finding is challenged
before it is emitted; the outcome travels with the finding.

```
ScoredSession + BehavioralFeatureSet + session + finding
        |
        v
  ARDEValidator
   |- consistency checks (10)        arde/consistency.py
   |- approved-activity registry     arde/approved_activities.py
   |- robustness assessment          arde/robustness.py
   |- explanation builder            arde/explain.py
   |- hash-chained audit log         arde/audit.py
        |
        v
  ValidationOutcome -> status (PASSED | PASSED_WITH_WARNINGS |
                               REVIEW_REQUIRED | REJECTED)
                     + robustness (ROBUST | MODERATE | FRAGILE)
        |
        v
  downgrade-only severity change + explanation attached to the finding
```

Contract highlights:

- **Challenge, never silence.** Statuses are data; an approval exception
  that matches is recorded, and one that does *not* match is recorded too.
- **Abstention is not innocence.** A check with missing telemetry returns
  `ABSTAINED`, which is evidence of incompleteness, not a pass.
- **Downgrade-only.** ARDE can lower severity (audited, reversible) but can
  never raise it.
- **Read-only.** A source scan (`test_arde_end_to_end.py`) rejects any
  remediation verb (delete/block/revoke/…) appearing in `arde/`.

## Part 5 — final-stage evaluation, contract & serving

```
15 scenario families ──> detector ──> labeled sessions
        |                                   |
        |                    chronology-safe feature preparation (no leakage)
        |                                   |
        |                 chronological train / validation / test split
        |                  (integrity proven disjoint + chronological)
        v                                   v
  variants A–E  ──  E = full stack + ARDE (REJECTED blocks an alert)
        |                                   |
        v                                   v
  full metrics  ──  threshold tuning (VALIDATION only)  ──  ablation
        |                                   |
        v                                   v
  error analysis (FP/FN)          output contract + dashboard view
        |                                   |
        v                                   v
  final_*.json artifacts            REST API (5 endpoints, WSGI)
```

Contract highlights:

- **No leakage.** The operating threshold is selected on the validation
  period and frozen; the test period is scored once. `verify_split_integrity`
  returns a machine-checkable disjoint/chronological report.
- **Honest ablation.** Leave-one-component-out marks a component's features
  `unavailable` (fusion renormalizes) or removes the ML model; deltas are
  measured on the same test period. The evaluation builds the frozen ML
  feature vector for every session, so the isolation-forest component is
  actually fitted and scored (its ablation shows a real PR-AUC delta). On the
  synthetic fixture, access-pattern removal costs the most ranking quality
  and volume/time removal *improves* headline metrics — named plainly rather
  than hidden.
- **Stable contract.** `output_contract.py` builds one flat, documented
  block per finding (`supporting_evidence` and `contradicting_evidence`
  always both present; `recommended_next_steps` are investigation-only).
- **Framework-neutral API.** `api/service.py` holds pure handlers;
  `api/router.py` maps paths; `api/wsgi.py::create_app` exposes a stdlib
  WSGI app. No web-framework dependency.
- **Determinism.** Session ids in the evaluation corpus are rewritten to a
  stable form (`eval-<scenario>-<instance>-<n>`) so artifacts are
  bit-identical across runs; only `final_performance.json` varies (it is a
  measurement, labelled as such).

## Storage schema

| Table | Purpose |
|---|---|
| `data_activity_events` | normalized events + indexes (actor/time, resource/time) |
| `data_access_sessions` | session payloads + window indexes |
| `data_resource_profiles` | per-resource observed history (upserted) |
| `data_baseline_versions` | immutable baseline versions |
| `exfiltration_findings` | discovery findings + ARDE payload |

Raw events are referenced via `raw_event_reference` (digest + unique
suffix) into the raw store, which redacts credential keys
(`password|secret|token|authorization|credential|accesskey|signature`,
case-insensitive) before persisting and re-verifies digests on read.

## Extension points for Part 4 (and Azure/GCP)

- `AnomalyDetector.fit/score` — swap the shipped IsolationForest behind
  the same interface; `BehavioralFeatureSet` carries
  value/availability/provenance per feature.
- XGBoost — implement behind `SupervisedModelGate` + `LabeledDataset`
  when correctly labeled data exists; the logistic trainer is a drop-in
  replacement point.
- Isotonic calibration — add alongside `PlattCalibrator`; selection by
  measured Brier/ECE on validation data.
- `EventNormalizer.normalize(provider, ...)` — Azure/GCP normalizers;
  schemas already reserve the providers.
- `BaselineEngine` — swap the in-memory store for the database behind the
  same record/stats/deviation interface.
- `DetectorConfig` + `FusionWeights` — all tuning knobs; experimentally
  tune weights per deployment, never claim universal optima.
