# Temporal Attack Progression Engine (Step 3C)

## 1. Objective
The Temporal Attack Progression Engine evaluates chronological sequences of security events to determine if they form a meaningful chronological progression associated with an attack behavior. It distinguishes between isolated suspicious events, loosely related events, and structured attack progressions.

## 2. Temporal Window
The engine groups events based on a configurable time window (default is 60 minutes). Events falling outside the time window boundaries will not be grouped into a single progression chain.

## 3. Event Ordering
Events are strictly ordered based on their actual reported `timestamp`. If an event is missing a timestamp, the sequence ordering is classified as `UNKNOWN`, leading to `INSUFFICIENT_EVIDENCE`.

## 4. Actor Continuity
The engine tracks actor identities across events. Sequences performed entirely by the same actor identity yield a higher progression score (Actor Continuity). If events involve disjoint actors without established relationships, they are scored lower or marked merely as `RELATED_EVENTS`.

## 5. Resource Continuity
The engine analyzes the target resources involved. When the same resource is targeted across multiple steps, resource continuity evidence strengthens the progression hypothesis.

## 6. Event Compatibility
Events are evaluated based on their taxonomy to ensure the sequence makes sense as an attack. Random assortments of events receive a lower score than recognized tactical combinations.

## 7. Progression Patterns
A provider-neutral pattern matching system evaluates sequences. Supported patterns include:
*   `CREDENTIAL_TO_PRIVILEGE_TO_ACCESS`: E.g., `LOGIN` -> `PERMISSION_CHANGED` -> `OBJECT_READ`
*   `CREDENTIAL_TO_EXFILTRATION`: E.g., `LOGIN` -> `OBJECT_READ` -> `DATA_EXPORT`
*   `MODIFICATION_TO_DESTRUCTION`: E.g., `RESOURCE_MODIFIED` -> `RESOURCE_DELETED`
*   `DESTRUCTION_AND_RECOVERY_SABOTAGE`: E.g., `MASS_DELETE` -> `BACKUP_DELETED`

## 8. Score Methodology
A deterministic score between 0.0 and 1.0 is built additively:
*   Temporal Order (in window): `+0.2`
*   Actor Continuity: `+0.3`
*   Resource Continuity: `+0.2`
*   Event Compatibility (Pattern Match): `+0.3`

## 9. State Model
*   `NO_SEQUENCE`: 0 or 1 valid events, or events out of window.
*   `RELATED_EVENTS`: Score < 0.45 (e.g. multiple events in window, but different actors/resources).
*   `PARTIAL_PROGRESSION`: Score 0.45 to 0.74 (e.g. same actor, but no specific pattern).
*   `STRONG_PROGRESSION`: Score >= 0.75 (same actor, matching pattern).
*   `INSUFFICIENT_EVIDENCE`: Missing timestamps or un-parsable data.

## 10. Evidence Traceability
Every contributing factor generates a `TemporalEvidence` object linking directly back to the original `event_ids`.

## 11. Observed/Inferred/Unknown
*   `OBSERVED`: Explicit matches like the same Actor ID or Resource ID.
*   `INFERRED`: Derived insights, such as events matching a known chronological pattern or occurring within a specific window.
*   `UNKNOWN`: Missing data leading to an inability to evaluate a factor.

## 12. False-Positive Considerations
A `STRONG_PROGRESSION` state does not automatically mean an attack is confirmed; it just indicates strong chronological and tactical correlation. Normal administrative sequences (like creating a user, assigning permissions, and the user reading a file) could trigger this. Context must be evaluated by the unified Activation engine.

## 13. Limitations
*   Events missing timestamps immediately halt progression correlation.
*   Duplicate events are intentionally squashed to avoid score inflation, meaning event spam (e.g., 500 read events) won't artificially max out the progression score.

## 14. Multi-Cloud Behavior
The engine relies exclusively on the normalized `SecurityEventCategory`. AWS, Azure, and GCP events are normalized upstream, meaning this temporal engine requires zero provider-specific logic.

## 15. Test Methodology
Tests execute directly against the `TemporalAttackProgressionEngine.evaluate()` function and validate:
*   Single event rejection
*   Reverse chronological sorting correction
*   Actor and resource continuity
*   Deduplication of overlapping events
*   Pattern recognition for data-access and sabotage
*   Tenant isolation
*   Determinism
