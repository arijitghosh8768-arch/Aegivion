# Ransomware / Data Destruction Detector

## 1. Detection Objective
The objective of this detector is to identify suspicious destructive behavior targeting cloud resources, indicative of ransomware, sabotage, or mass data deletion. It is an independent node relying strictly on observable event properties and tenant-bounded historical baselines.

## 2. Supported Attack Behaviors
- **Mass Deletion**: Spikes in deleted objects exceeding baselines.
- **Mass Modification**: High-volume modifications indicative of encryption or overwrite operations.
- **Backup/Snapshot Destruction**: Specific destruction of recovery mechanisms.
- **Encryption-like Activity**: KMS/Encryption API actions correlated with modification logic.

## 3. Input Events
- **SecurityEvent**: A normalized event tracking actions like `OBJECT_DELETE`, `OBJECT_MODIFIED`.
- **Digital Twin Context**: Historical data providing baselines (`actor_baseline_deletions`, `actor_baseline_modifications`) and historical target scopes.

## 4. Detection Signals
- **Single Ordinary Delete**: A normal baseline deletion (adds marginal weight).
- **Abnormal Mass Deletion/Modification**: Extracted from event metadata (e.g., `objects_deleted`) scaling past 5x the historical baseline.
- **Backup Destruction**: Matches against critical keywords (`snapshot`, `backup`, `recovery`) in destructive API calls.
- **Encryption Configuration**: Matches `encrypt` or `kms` APIs.
- **Strong Historical Deviation**: Activity on resources entirely unseen in the identity's historical profile.

## 5. Scoring Methodology
Scoring is additive and capped at `1.0`. Threshold is `>= 0.5`.
- Single delete: `+0.05`
- Repeated delete (>1 object): `+0.25`
- Abnormal mass deletion (>10 objs & >5x baseline): `+0.35`
- Abnormal mass modification (>10 objs & >5x baseline): `+0.25`
- Backup/snapshot destruction: `+0.35`
- Encryption-related modification: `+0.25`
- Strong historical deviation: `+0.20`

## 6. Evidence Model
Uses the `DetectionEvidence` schema referencing concrete event IDs, avoiding any fabrication of missing metadata.

## 7. Observed / Inferred / Unknown Semantics
- **Observed**: Explicit object counts within the event payload (e.g., `objects_deleted=100`).
- **Inferred**: Abnormal mass classification (derived from baseline comparison).
- **Unknown**: If an event lacks volume metadata, it is treated as a single object action.

## 8. False-Positive Considerations
A single snapshot deletion (`+0.35 + 0.05 = 0.40`) remains below the threshold. It requires compounding evidence (such as being an unhistorical target `+0.20`) to flag as genuinely suspicious. Routine administrative cleanups will generate low scores.

## 9. Current Limitations
- **Encryption Certainty**: We cannot definitely claim files are encrypted just because an encryption API was used. We can only flag the presence of the API.
- **State Aggregation**: Similar to Step 2C, single-event evaluation relies heavily on upstream Digital Twin contexts maintaining robust rolling baselines.

## 10. Test Coverage
Extensively covered in `test_ransomware_destruction_detector.py`, validating backup destruction, missing baseline resilience, and tenant isolation.

## 11. Independence
Runs completely independently of credential compromise or data exfiltration detectors, preserving architectural decoupled design.

## 12. Why this is Detection rather than Attack Activation
This detector answers "Did suspicious destruction occur?", not "Is this an active attack chain progressing toward domain takeover?". Determining if a localized ransomware event threatens broader systemic viability belongs to Step 3.
