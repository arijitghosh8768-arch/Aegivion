# Step 6A - Aegivion Agent Controller

## Objective
Phase 6 converts Aegivion from a collection of deterministic security engines into a continuously operating orchestration system. Step 6A introduces the `AegivionAgentController`—a deterministic state machine that manages the worker lifecycle and event routing, acting as the "nervous system" of the platform.

## Agent Architecture
```text
          CONTINUOUS AGENT
                 │
      ┌──────────┴──────────┐
   EVENTS                 HEALTH
      │                     │
      ▼                     ▼
   QUEUE              HEARTBEATS
      │
      ▼
   ROUTING
```
- **Controller Responsibilities**: Lifecycle management, queue handling, deterministic routing, health checks, heartbeats, and correlation tracking.
- **Worker Responsibilities**: Domain execution (e.g., Detection, Activation, Response). The controller orchestrates, but it never executes domain logic itself.
- **Workers**: `EVENT_INGESTION`, `DETECTION_CORRELATION`, `ACTIVATION_RISK`, `RESPONSE_VERIFICATION`.

## Key Invariants & Safety
- **No Infinite Restarts**: The system degrades or fails closed rather than blindly entering uncontrolled restart loops.
- **Tenant Isolation**: Events are strictly bound by `organization_id`. The controller drops events that don't match the agent's assigned tenant.
- **No AI Execution Authority**: Direct triggers from AI or LLM sources are fundamentally blocked from execution.
- **Zero Cloud Mutation**: The controller itself has zero dependencies on `boto3` or cloud adapters. The response pipeline (`5A-5F`) is preserved exactly as tested.
- **Failure Isolation**: A single worker failure transitions the controller to a `DEGRADED` state, keeping healthy workers online while isolating the fault.
