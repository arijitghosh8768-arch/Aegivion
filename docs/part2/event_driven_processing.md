# Step 6C - Event-Driven Processing

## Objective
Step 6C integrates the independent deterministic security engines into the continuous Agent runtime without altering their underlying algorithms. The runtime serves strictly as an orchestration layer, allowing events to naturally cascade through the pipeline while enforcing isolation, validation, and execution safety.

## Agent Execution Modes
The controller and its workers operate strictly under three predefined modes:
- **`STOPPED`**: Idle, discarding inputs, safe termination state.
- **`OBSERVE_ONLY`**: The default state. Complete analysis (ingestion → detection → temporal → risk → activation → prediction → response optimization → simulation → safety policy) runs continuously, but all cloud execution capabilities are hard-disabled.
- **`CONTROLLED_RESPONSE`**: Allows the Response Verification Worker to proceed to the existing `ExecutionOrchestrator` if and only if the Safety Policy dictates `ALLOW`.

## The Pipeline Lifecycle
1. **Event Ingestion**: Normalizes cloud events and creates the bounded `AgentEvent` envelope with strict tenant bindings.
2. **Detection & Correlation**: Synchronously loops over the existing independent detectors (`CredentialCompromiseDetector`, `DataExfiltrationDetector`, `RansomwareDestructionDetector`). Emits `DETECTION_COMPLETED` for suspicious findings.
3. **Activation & Risk**: Consumes detections. Integrates the `TemporalAttackProgressionEngine`, `DynamicAttackPathEngine`, `UnifiedAttackActivationEngine`, and `NextStagePredictionEngine`. Emits `ACTIVATION_ANALYSIS_COMPLETED`.
4. **Response & Verification**: Consumes activated attack paths. Performs `WhatIfSimulationEngine` and `MinimumImpactResponseEngine` scoring. Final check against `ResponseSafetyPolicyEngine`. In `CONTROLLED_RESPONSE` mode, securely hands off to the `ExecutionOrchestrator`.

## Security Boundaries
- **No Engine Rewrites**: The workers do not duplicate the formulas of the engines. They only manage the state transitions between them.
- **AI/LLM Block**: Direct event sources from `AI_DIRECT` or similar channels are forcefully dropped at the controller ingestion bound. AI cannot become an execution authority.
- **Fail Closed**: Any failure inside the pipeline emits a `PIPELINE_ERROR` event that safely cascades to failure without corrupting neighboring tenant operations or triggering unauthorized responses.
