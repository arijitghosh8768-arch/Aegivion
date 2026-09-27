# Data Exfiltration Detector

## 1. Detection Objective
The objective of this detector is to identify suspicious data access or movement behavior that could indicate data exfiltration. It operates independently as a pure detection node, without applying predictive AI or executing automated responses.

## 2. Input Data
- **SecurityEvent**: A normalized event tracking actions like `OBJECT_READ`, `DATABASE_READ`, or `DATA_EXPORT`.
- **Digital Twin Context**: Historical data access context securely bounded to the tenant (e.g., baseline transfer volumes, sensitive asset lists, known historical targets).

## 3. Detection Signals
The detector relies strictly on observable evidence:
- **Abnormal Data Read**: Any standard object read event (baseline activity).
- **Data Access Volume**: High metadata byte counts drastically exceeding the actor's historical baseline.
- **Resource Sensitivity**: Accessing an asset explicitly marked as sensitive in the Twin context.
- **Behavioral Anomaly**: Accessing a resource the identity has never historically targeted.
- **Data Movement**: Transferring data to a target tagged as an `external` network zone.

## 4. Scoring Methodology
Scoring is additive and deterministic (capped at `1.0`). A score of `>= 0.5` flags the event as suspicious.
- Base Read Event = `+0.1` (Normal usage will stay at 0.1)
- Sensitive Asset Access = `+0.3`
- Unusually Large Volume = `+0.4`
- Unhistorical Target Access = `+0.2`
- External Destination Transfer = `+0.4`

## 5. Evidence Model
All identified anomalies result in `DetectionEvidence` objects appended to the `DetectionResult`. Every piece of evidence strictly references the originating `event_id`.

## 6. Observed / Inferred / Unknown Semantics
- **Observed**: Event attributes (bytes transferred, action name).
- **Inferred**: Statistical derivations (exceeding baseline by 10x).
- **Unknown**: Handled gracefully. Missing metadata (e.g., volume sizes) simply bypasses the volume check.

## 7. False-Positive Considerations
A normal `GetObject` event only yields `0.1` and will not trigger a detection. Even reading a sensitive asset yields `0.4` (0.1 + 0.3), meaning it requires at least one compounding factor (like unhistorical access or massive volume) to push it into the suspicious range (`0.5+`). 

## 8. Current Data Limitations
- Sequential collection behavior (e.g., aggregating 100 separate read events) is difficult to score linearly on single-event evaluation without relying on heavy state aggregation. Currently handled via `actor_baseline_volume` tracking.

## 9. Test Coverage
Covered under `test_data_exfiltration_detector.py` validating volume spikes, false positives on normal reads, and tenant context isolation.

## 10. Why the Detector is Independent
Data Exfiltration does not require a prior credential compromise to exist (e.g., insider threats or misconfigured public buckets). Keeping it independent ensures robust standalone defense.
