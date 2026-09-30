# Next-Stage Attack Prediction (Step 4A)

## 1. Purpose
The purpose of Next-Stage Attack Prediction in Aegivion is to deterministically estimate the most plausible next attack stage based on observed evidence. It answers: "Given what has already happened, what attack stage is most likely to occur next?"

## 2. Architecture
The prediction layer sits after unified attack activation and before any simulation or response components:
```text
Detection
   ↓
Activation
   ↓
Prediction
```
It builds its reasoning based on the current context provided by underlying engines (Detection, Path Risk, Temporal Progression) without duplicating their logic.

## 3. Inputs
The engine consumes:
- `explicit_current_stage` (optional, to force the current stage)
- `DetectionResult` (provides Detection Support and potentially infers the current stage)
- `UnifiedAttackActivationResult` (tenant isolation context)
- `DynamicAttackPathRiskResult` (provides Attack Path Support and Resource Continuity)
- `TemporalProgressionResult` (provides Temporal Evidence and Actor Continuity)

## 4. Algorithm
The engine evaluates all candidate next stages from the current stage using the following weighted formula (normalized to 0.0 - 1.0):
```text
PredictionScore =
    TransitionPrior (0.15)
  + TemporalEvidence (0.25 * Temporal Score)
  + ActorContinuity (0.15 * [1.0 if present])
  + ResourceContinuity (0.15 * [1.0 if path exists])
  + AttackPathSupport (0.20 * Path Score)
  + DetectionSupport (0.10 * Detection Score)
```

## 5. Transition Graph
The engine uses a deterministic graph to map valid transitions:
*   `INITIAL_ACCESS` → `CREDENTIAL_COMPROMISE`
*   `CREDENTIAL_COMPROMISE` → `PRIVILEGE_ESCALATION`, `RESOURCE_ACCESS`
*   `PRIVILEGE_ESCALATION` → `RESOURCE_ACCESS`, `LATERAL_MOVEMENT`, `DEFENSE_EVASION`
*   `RESOURCE_ACCESS` → `DATA_COLLECTION`, `DATA_EXFILTRATION`, `LATERAL_MOVEMENT`
*   `DATA_COLLECTION` → `DATA_EXFILTRATION`
*   `DATA_EXFILTRATION` → `DESTRUCTION`
*   `DESTRUCTION` → `RECOVERY_SABOTAGE`

## 6. Evidence Provenance
Every reasoning element is classified to ensure strict provenance:
*   **OBSERVED**: Direct measurements (e.g., "Actor continuity confirmed in temporal data").
*   **INFERRED**: Derived from models (e.g., "Path risk support score 0.8").
*   **PREDICTED**: The final resulting next stage.
*   **UNKNOWN**: Missing inputs explicitly labeled to prevent assumptions (e.g., "UNKNOWN: Temporal evidence missing").

## 7. Safety Boundary
**Prediction is strictly read-only and cannot execute remediation.** It does not mutate cloud state, delete IAM users, execute runbooks, or invoke response adapters. It provides input strictly for Step 4B (Simulation) and Step 4C (Response Selection).

## 8. Limitations
- **Deterministic baseline**: Relies on a hardcoded, limited transition taxonomy.
- **Dependency on Digital Twin**: Prediction quality depends heavily on the accuracy of the underlying path risk and temporal data.
- **Incomplete visibility**: Missing telemetry directly reduces prediction confidence.
- **Ambiguity**: Legitimate administrative activities can mimic attack progression, meaning a prediction does not definitively establish attacker intent.

## 9. Future Research
While the current implementation is deterministic, future phases could explore:
- ML-based transition learning
- Bayesian prediction models
- Sequence models (Transformers, LSTMs)
- Historical attack replay for training
- Adaptive transition probabilities based on environment-specific baselines
