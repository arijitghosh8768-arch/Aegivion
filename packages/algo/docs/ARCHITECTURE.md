# Architecture — Cloud Destructive Activity Detector (Parts 1–5)

## Pipeline

```
provider telemetry              ingestion/aws                  detection/cloud_destruction
──────────────────              ─────────────                  ───────────────────────────
CloudTrail records ───────────► cloudtrail_resource_activity ─┐
EventBridge aws.backup ────────► backup_events ────────────────┤
EventBridge snapshots ─────────► snapshot_events ──────────────┤
Azure Activity Log ────────────► azure/activity_log ───────────┤
GCP Cloud Audit Logs ──────────► gcp/audit_log ────────────────┤
                                                               │
                                    ┌──────────────────────────┘
                                    ▼
                        ResourceActivityNormalizer
                        (protection-catalog enrichment)
                                    │
                                    ▼
                    ResourceActivityEvent (canonical, self-describing:
                    feature_availability + data_provenance)
                                    │
                                    ▼
                    DestructiveSessionBuilder   ResourceProfileBuilder
                                    │                    │
                                    ▼                    ▼
                    DestructiveActivitySession   ResourceProtectionProfile
                                    │                    │
                                    └────────► DestructionRepository (SQLAlchemy)
                                                 │
                                                 ▼
                Part 2 behavioral layer (deterministic, no ML)
                ─────────────────────────────────────────────
                evidence.SessionEvidence      shared per-session counters
                        │
        ┌───────────────┼──────────────────────────────┐
        ▼               ▼                              ▼
  baseline.py      modification.py deletion.py    snapshot.py backup.py
  (per-actor normal, versioning.py                rewrite.py sequence.py
   quality +       (deviation vs baseline)        temporal.py
   POISONING DEFENSE)
        │                                              │
        └──────────────► features.SessionFeatureVector ◄┘
                         (per-feature MeasuredValue:
                          value + availability + provenance)
                                    │
                                    ▼
                Part 3 fusion layer
                ─────────────────────────────────────────
                feature_vector.py   versioned numeric ML vector
                anomaly.py          Isolation Forest → anomaly_score
                sequence_model.py   transition rarity/structure → seq score
                temporal_features.py 9 metrics × 6 mandated windows
                supervised.py       optional XGBoost/logistic slot
                        │
                        ▼
                scorer.py (config-weighted destruction_risk)
                        │                    │
                        ▼                    ▼
                confidence.py          finding.py (severity policy,
                (evidence quality;      version stamps, audit blocks)
                 risk ≠ confidence)
                        │
                        ▼
                detector.DestructionDetector.detect() → DetectionOutcome
                replay.ReplayEngine (deterministic, digest-verified)
                evaluation.evaluate_variants (5-variant comparison)
                        │
                        ▼
                Part 4 response orchestration
                ─────────────────────────────────────────────────
                response.ResponsePolicy   (versioned playbook:
                                         severity → action set,
                                         cooldown, per-finding cap)
                response.ResponseOrchestrator
                  plan()  → ResponsePlan (approval-aware, idempotent)
                  execute() → ActionStatus per action
                  APPROVAL_REQUIRED: REVOKE_SESSION, REVOKE_CREDENTIALS,
                  DISABLE_USER, ISOLATE_RESOURCE, QUARANTINE_RESOURCE
                        │
                        ▼
                Part 5 Threat-Correlation seam (outside this package)
                ─────────────────────────────────────────────────
                correlation.ThreatCorrelationBroker
                  submit()         one-way, idempotent (content digest)
                  attach_context() additive-only, never mutates scores
                  acknowledge() / pending_review()  explicit workflow
                imports nothing from detection.* or ingestion.*
```

## Data flow rules

1. **Normalization is total.** Every input record ends in exactly one
   disposition: `normalized`, `skipped` (valid but out of scope), or
   `quarantined` (malformed). Nothing is silently dropped.
2. **Events are self-describing.** Each canonical event carries per-field
   availability (`available / unavailable / derived / enriched` with a
   machine-readable reason) and lineage (`DataProvenance`: source type,
   pipeline, raw reference, replay/synthetic flags, normalizer version).
3. **Sessions are observational.** The builder groups by actor
   (+ account/region when keyed), splits on idle gaps > 30 min (config),
   force-splits at 12 h (config), and sums per-category counters. No verdicts.
4. **Deviation is relative and explainable.** Every behavioral
   `*_deviation` / `*_anomaly` maps observed-vs-baseline to `[0, 1]`
   (1.0 at the configured factor over normal, linear below), keeps raw
   counters in `MeasuredValue.raw`, and is `None` when no trusted baseline
   exists — never a fabricated zero.
5. **Baselines never learn attacks.** `classify_contamination` grades each
   historical session LOW / MEDIUM / HIGH / CRITICAL from evidence counters
   (protection changes, version scrubbing, recovery-impairing volume,
   destructive ratio). HIGH/CRITICAL are excluded from learning; MEDIUM has
   0.25 weight unless an approved profile matches; CRITICAL is never
   automatically learned. Baseline builds are versioned and prior
   generations are retained (`BaselineStore.history`).
6. **Leave-one-out.** Feature extraction builds the analyzed session's
   baseline from the *other* sessions only and never persists it, so
   analysis cannot contaminate the operational baseline store.
7. **Independence of concerns.** `protection_degradation` (posture changes)
   is computed independently of `recovery_destruction` (deleted recovery
   state) and `recoverability` (remaining recovery paths).
4. **Profiles are descriptive.** Rates are history ÷ observed days. Baseline
   statistics and deviation judgement are Part 2.

## Key invariants (test-enforced)

- Risk, confidence and severity exist **only** on findings/fusion outputs;
  canonical events and Part 1 sessions stay score-free
- Risk ≠ confidence (separate engines; confidence is never `risk / 100`)
- Every behavioral feature is a `MeasuredValue`: absent evidence is
  `None` + reason, never a fabricated zero; fusion redistributes missing
  weight and reports `missing_evidence`
- Severity CRITICAL requires evidence (confidence floor), never volume alone
- Supervised labels must be declared or explicitly synthetic; synthetic
  results carry `label_source="synthetic"` and are never presented as
  production performance
- Replay: same events + config + versions ⇒ same scored result
  (content digest, volatile uuids excluded)
- No imports or references to `Aegivion_algo_1` / `Aegivion_algo_2`
  (`test_independence.py`: AST import scan, source scan, runtime isolation)
- Canonical schema round-trips through storage losslessly

## Extension: adding a provider

1. Add a normalizer method on `ResourceActivityNormalizer` (or a standalone
   module under `ingestion/<provider>/`) that emits `ResourceActivityEvent`.
   See `ingestion/azure/activity_log.py` and `ingestion/gcp/audit_log.py`
   for the contract (normal / skip / quarantine dispositions, raw actions as
   evidence, attempts as evidence, provider ids preserved as `resource_arn`).
2. Map provider-specific actions onto `ActionCategory`; keep raw actions in
   `raw_action`.
3. Implement a `ProtectionCatalog` for the provider's protection APIs.
4. No changes are needed in session/profile/storage layers — schemas are
   provider-neutral.

## Extension: response + correlation

- **Response (Part 4)** lives entirely inside this package and is
  *plan-first*: `ResponseOrchestrator.plan()` produces an approval-aware,
  idempotent plan; destructive actions in `APPROVAL_REQUIRED` are planned but
  only executed when a handler is wired and the approval gate is passed.
  Cooldown state and per-finding caps bound blast radius; every action id is
  a content digest so replans are stable.
- **Threat Correlation (Part 5)** lives in `correlation/`, outside every
  algorithm package, and is the *only* cross-algorithm seam. Flow is
  one-way (`submit`), context is additive-only, and correlation records are
  immutable snapshots — findings keep their own risk/confidence/severity.
