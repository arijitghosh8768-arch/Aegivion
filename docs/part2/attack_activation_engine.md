# Attack Activation Engine

The Attack Activation Engine evaluates whether an existing `DetectionResult` represents evidence that an attack path is becoming active within the environment.

## 1. Detection vs Attack Activation
- **Detection**: Asks "What suspicious behavior occurred?" Evaluates individual signals to build confidence that an anomaly is malicious.
- **Attack Activation**: Asks "Does this suspicious behavior correspond to a viable attack path, and is there evidence that the path is currently being activated?"

## 2. Inputs
The engine consumes:
- `DetectionResult` from an independent detector.
- Trusted `Security Digital Twin` state (relationships, exposure).
- `SecurityEvent` history for temporal context.

## 3. Digital Twin Relationship Model
The Digital Twin provides context based on `CloudIdentity`, `CloudAsset`, and `AssetRelationship` nodes. It ensures all context is tenant-isolated, scoped strictly to the provided trusted `organization_id`.

## 4. Identity/Privilege Analysis
If the actor identity involved in the detection has privileged permissions (e.g. `admin`, `write`), the activation score increases. Missing identities result in `INSUFFICIENT_EVIDENCE`.

## 5. Reachability
The engine queries if the actor can reach the target asset via the graph. If unreachable, the activity does not represent a valid attack path traversal.

## 6. Asset Criticality
Assets flagged as critical (e.g., databases, production environments) increase the activation score, prioritizing threats with higher potential blast radii.

## 7. Temporal Progression
The engine evaluates activity across an `ATTACK_ACTIVATION_WINDOW_MINUTES` window. Multiple sequenced anomalies indicate intentional attack path traversal, raising the score.

## 8. Path Completeness
- `NO_PATH`: No valid relation.
- `PARTIAL_PATH`: Incomplete or indirect relationship.
- `VALID_PATH`: Complete viable path from actor to target.
- `HIGH_RISK_PATH`: Fully valid path including highly privileged hops.

## 9. Activation State Machine
- `INACTIVE`: Low score or no valid path.
- `POTENTIAL`: Partial path or moderate score.
- `ACTIVATING`: Valid path with >= 0.5 activation score.
- `ACTIVE`: Valid path with >= 0.8 activation score.
- `INSUFFICIENT_EVIDENCE`: Missing identity or critical context.

## 10. Activation Score Formula
Base score is purely additive (0.0 to 1.0):
- Detection Suspicious: +0.3
- Privileged Access: +0.2
- Asset Criticality: +0.2
- Resource Reachability: +0.3 (if valid path) / +0.1 (if partial path)
- Temporal Progression: +0.2 (if multiple chained events)
Capped at `1.0`.

## 11. Evidence Semantics
Factors are categorized as:
- `OBSERVED`: Directly present in stored data (e.g. privileges, target ID).
- `INFERRED`: Derived by the activation algorithm (e.g. temporal sequence, reachability).
- `UNKNOWN`: Missing data.

## 12. False-Positive Handling
A detection anomaly on an isolated, unreachable, or unprivileged identity gracefully falls to `INACTIVE`. Only the convergence of privilege, reachability, and detection raises an alert.

## 13. Limitations
- Path checks rely entirely on populated Digital Twin relationships.
- Missing historical events inhibit temporal progression scoring.
- Does not simulate future events (Prediction).

## 14. Test Methodology
Tests assert:
- Tenant isolation constraints.
- Score ceilings and state machine boundaries.
- Graceful degradation on missing metadata.
- Independence from detector logic (consumes `DetectionResult` directly).
- Deterministic output.
