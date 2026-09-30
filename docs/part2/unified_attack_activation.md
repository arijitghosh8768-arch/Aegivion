# Unified Attack Activation (Step 3D)

## 1. Why Detection and Activation are Separate
Detection confirms that suspicious behavior has occurred (e.g., unusual login). Activation confirms whether that behavior is successfully leveraging a viable path through the environment to reach a target. Separating them prevents alerts for highly suspicious behavior that lacks a structural path to any meaningful asset.

## 2. Three Input Dimensions
The engine consumes three independent analytical dimensions:
1.  **Detector Confidence**: How suspicious is the observed behavior?
2.  **Path Risk**: How dangerous is the reachable attack path structurally?
3.  **Temporal Progression**: How strongly do the observed events form a chronological and logical progression?

## 3. Score Formula
The Unified Activation Score (0.0 to 1.0) is a weighted combination of the three inputs, subject to specific gating rules.

## 4. Component Weights
If all three components are present:
*   `Detector Confidence`: 40%
*   `Path Risk`: 40%
*   `Temporal Progression`: 20%

If temporal evidence is missing (UNKNOWN):
*   `Detector Confidence`: 50%
*   `Path Risk`: 50%

## 5. Path Gating
Path Risk acts as a gate. If no viable path exists (`path_risk < 0.1` or missing), the overall activation score is severely capped (max `0.49`, state `POTENTIAL`), regardless of how high the detector confidence or temporal progression is. High detection without a path means the attack cannot progress.

## 6. Temporal Evidence
Temporal progression serves to elevate a score into higher confidence. If temporal evidence is present and strong, it pushes the state toward `ACTIVE`.

## 7. Missing-Data Handling
If an input is missing, it is treated as `UNKNOWN`, not 0.0 or 1.0. 
*   Missing path risk triggers path gating.
*   Missing temporal data removes the 20% temporal bonus and limits the maximum achievable score to 0.79 (`ACTIVATING`), preventing an `ACTIVE` state without temporal confirmation.

## 8. State Thresholds
*   `0.00 – 0.24`: **INACTIVE**
*   `0.25 – 0.49`: **POTENTIAL** (Capped here if no viable path)
*   `0.50 – 0.79`: **ACTIVATING** (Capped here if no temporal evidence)
*   `0.80 – 1.00`: **ACTIVE**
*   `INSUFFICIENT_EVIDENCE`: When all inputs are missing.

## 9. Evidence Traceability
The unified result (`UnifiedAttackActivationResult`) preserves the original scores and logs `UnifiedEvidence` entries indicating exactly how much each dimension contributed to the final score, including any applied caps (e.g., `TEMPORAL_GATING`, `PATH_GATING`).

## 10. Observed / Inferred / Unknown
*   **OBSERVED**: Direct measurements.
*   **INFERRED**: The unified score and applied gating logic.
*   **UNKNOWN**: Missing inputs that are explicitly ignored rather than fabricated.

## 11. Multi-Cloud Behavior
The engine is completely provider-neutral. It relies on the generic scores provided by the underlying normalized engines, ensuring it works seamlessly across AWS, Azure, and GCP.

## 12. Tenant Isolation
Tenant isolation is enforced strictly. If the `organization_id` of the DetectionResult, PathRiskResult, or TemporalProgressionResult do not match, the engine raises an immediate `ValueError`, preventing cross-tenant data merging.

## 13. False-Positive Handling
*   **High Detector, Low Path**: A highly suspicious event with no path to a critical resource is capped at `POTENTIAL`.
*   **Legitimate Admin (High Temporal, Low Path/Detector)**: A normal sequence of admin events lacks malicious detection and viable risk, keeping it `INACTIVE` or `POTENTIAL`.

## 14. Limitations
The score relies entirely on the accuracy of the underlying detectors and path models. If the digital twin is out of date, the path risk will be inaccurate, skewing the activation score.

## 15. Why this is not Prediction
The activation score describes the *current* state of evidence. It answers "Is a path currently active?" not "What will the attacker do next?"

## 16. Why this is not Response
The engine computes a deterministic score based on evidence. It does not invoke AWS APIs, delete IAM users, or execute remediation playbooks.
