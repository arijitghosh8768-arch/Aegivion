# Phase 6E: Continuous Activation, Dynamic Risk & Attack-State Tracking

## Objective
Phase 6E transforms the activation and risk scoring pipeline into a continuously evolving security state tracker. It ensures that as new detections and correlations emerge from the 6D detection context, the risk and activation scores are updated seamlessly, transitioning an attack state over time from `POTENTIAL` to `ACTIVE` and eventually to `CONTAINED`.

## Security Attack State Tracker
The `SecurityAttackStateTracker` represents the continuous lifecycle of a correlated sequence of detections.

- **State Transitions**: `NO_ACTIVITY` -> `POTENTIAL` -> `ACTIVATING` -> `ACTIVE` -> `CONTAINED` -> `VERIFIED_RESOLVED`.
- **Tenant Isolation**: Attack states are rigorously isolated per tenant (`org_id`).
- **Escalation Only**: Automatic score reassessment handles only escalation. Containment or resolution downgrades require explicit manual or automated verified responses to avoid flapping states.
- **Continuous Recalculation**: Instead of scoring statically per event, the `ActivationRiskWorker` pushes new temporal, risk, and activation scores into the state tracker.
- **Transition History**: Each context retains a full transition list with reasons (score thresholds crossed) for auditing and research purposes.

## Integration
`ActivationRiskWorker` processes `DETECTION_COMPLETED` and `CORRELATION_COMPLETED` events, invoking:
1. `TemporalAttackProgressionEngine`
2. `DynamicAttackPathRiskEngine`
3. `UnifiedAttackActivationEngine`
4. `NextStagePredictionEngine`
5. `SecurityAttackStateTracker`

It then outputs `ACTIVATION_ANALYSIS_COMPLETED` featuring not just risk values but the precise evolving `attack_state` and history.

## Research Value
Because 6E operates by tracking the continuous lifecycle of an evolving attack across time (with predictive inputs), the framework naturally mirrors realistic APT behaviors and allows structured independent validation of the predictive engine and temporal risk model without blending them into a single black-box LLM score.
