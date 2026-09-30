# Phase 6D: Continuous Detection & Correlation

## Objective
Phase 6D transforms the event-driven pipeline into a continuously correlating security detection system. It focuses exclusively on the orchestration layer, ensuring that events are accurately evaluated and correlated over a bounded time window without duplicating or altering the underlying deterministic detection engines.

## Detection Context Store
The `DetectionContext` acts as a highly constrained, bounded in-memory store for recent security events and generated detections. 

- **Tenant Isolation**: Data is strictly partitioned by `org_id`. It is impossible to correlate Event A from Org A with Event B from Org B.
- **Capacity Bounds**: Context is bounded by `MAX_EVENTS_PER_TENANT` (1000) and `MAX_DETECTIONS_PER_TENANT` (500).
- **Temporal Bounds**: Observations are bounded by a fixed `MAX_WINDOW_MINUTES` (60 minutes).
- **Eviction Strategy**: Older events are evicted first based on timestamp (expired time), and subsequent capacity eviction truncates the oldest remaining entries.
- **Idempotency**: Adding an event with a duplicate `event_id` is silently ignored, preventing unlimited detections. Events are ordered strictly by `timestamp ASC` then `event_id ASC` for determinism.

## Correlation Architecture
The `DetectionCorrelationEngine` combines independent `DetectionResults` into sequences.

- **Determinism**: The engine applies straightforward correlation rules rather than opaque AI inferences. 
- **Controlled Correlation Types**: Outputs are limited to explicit correlation categories, such as `CREDENTIAL_TO_EXFILTRATION` or `MODIFICATION_TO_DESTRUCTION`. 
- **Deterministic Identity**: A new detection correlation identity is generated deterministically using `SHA256(org_id + detection_ids + correlation_type)`.
- **False-Positive Boundaries**: Legitimate related activities (e.g. administrator tasks) might generate `RELATED` states, but they won't automatically trigger high scores or `STRONGLY_CORRELATED` findings without matching established multi-stage attack types (which also factor into activation, managed independently).

## Event Flow & Integration
1. Event arrives as `SECURITY_EVENT_INGESTED` to the `DetectionCorrelationWorker`.
2. Event is logged into the `DetectionContext` under the specific `org_id`.
3. Independent detectors (`CredentialCompromiseDetector`, `DataExfiltrationDetector`, `RansomwareDestructionDetector`) run against the event.
4. If one or more detections are positive, they are logged in the `DetectionContext`.
5. The `DetectionCorrelationEngine` is invoked to evaluate the new detection(s) against related historical detections.
6. A `DETECTION_COMPLETED` event is emitted.
7. If correlation succeeds, a `CORRELATION_COMPLETED` event is also emitted.
8. These events progress directly into the `ActivationRiskWorker`.

## Boundaries & Limitations
- **No Cloud Mutation**: The correlation engine only reads and analyzes signals. It does not trigger cloud remediation.
- **No Engine Rewrites**: The scoring logic inside individual detectors and the risk pathways remain unchanged.
- **Incident Boundary**: This phase produces correlation context (`CorrelationResult`) but does not implement full incident management, ticket creation, or case tracking.
- **AI Restricted**: AI cannot create evidence, bypass tenant isolation, or modify deterministic detection paths. AI remains an explanation layer.
