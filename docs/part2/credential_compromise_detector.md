# Credential Compromise Detector

## 1. Detection Objective
The objective of this detector is to identify suspicious behavior that indicates a cloud identity's credentials have been compromised. It strictly focuses on **detection** of observable anomalies without executing prediction or response logic.

## 2. Input Data
- **SecurityEvent**: A normalized event representing a single cloud action.
- **Digital Twin Context**: Historical context for the actor (e.g., known IPs, recent failed logins) securely bounded to the tenant's organization.

## 3. Signals
The detector evaluates the following deterministic signals:
- **Source Anomaly**: IP addresses previously unseen for the identity.
- **Authentication Anomaly**: Successful logins immediately following multiple failed attempts.
- **Privilege Anomaly**: Suspicious modifications to IAM policies or roles.

## 4. Scoring Logic
Scoring is additive and deterministic, capped at `1.0`. The event is flagged as suspicious if the score reaches `0.5`.
- Unknown IP: `+0.3`
- Successful login after 3+ failures: `+0.5`
- IAM privilege modification: `+0.4`

*Note: This is a confidence score, NOT an Attack Activation Score.*

## 5. Evidence Model
Every triggered signal generates a `DetectionEvidence` object tracing back to the specific `event_id`, ensuring full explainability.

## 6. Observed vs Inferred vs Unknown
- **Observed**: Explicit fields from the `SecurityEvent` (e.g., source IP, event name).
- **Inferred**: Derived conclusions (e.g., "Suspicious login after 5 failures").
- **Unknown**: Handled safely without fabrication (e.g., missing actor IDs map to `None`).

## 7. False-Positive Handling
A single weak signal (like an unknown IP yielding `0.3`) does not cross the `0.5` threshold, preventing normal behavioral drifts from generating false alerts.

## 8. Limitations
- Does not currently perform geographic anomaly detection due to lack of a GeoIP dependency.
- Relies on the Digital Twin to accurately track state such as `recent_failed_logins`.

## 9. Test Coverage
Comprehensive test suite located at `test_credential_compromise_detector.py`, covering idempotency, missing fields, false positives, and tenant isolation.

## 10. Architectural Independence
This detector outputs a `DetectionResult`. It does not propagate graphs, mutate cloud state, or calculate activation paths. It is exclusively an analytical node in Step 2.
