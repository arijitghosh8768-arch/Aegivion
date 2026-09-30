# Step 6B - Worker Runtime & Lifecycle

## Objective
Step 6B establishes the dedicated runtime wrappers for each stage of the Aegivion pipeline:
1. `EventIngestionWorker`
2. `DetectionCorrelationWorker`
3. `ActivationRiskWorker`
4. `ResponseVerificationWorker`

## Architecture
Rather than executing synchronously on the agent controller's main thread, each worker runs an isolated `asyncio` background loop (via `AsyncQueueWorker`).

```text
CONTROLLER 
   │
   ▼ await handle_event(event) (returns instantly)
   │
   ▼
WORKER QUEUE (Bounded)
   │
   ▼ _process_loop (Background Task)
   │
   ▼ process_event(event) (Domain Logic)
```

## Key Invariants
- **Asynchronous Isolation**: The controller never waits for domain execution. It only waits for queue insertion.
- **Strict Backpressure**: If a worker's internal queue fills up, `handle_event` raises a backpressure exception immediately. The controller safely captures this and increments its own `failed_events` metric.
- **Exception Survival**: If domain logic throws an unhandled exception, the worker catches it, increments its `failed_count`, but **keeps the background loop alive**. Malformed events cannot crash the pipeline.
- **Heartbeat Safety**: The worker's `get()` on its queue times out every 1 second, explicitly to allow a heartbeat emission even when idle. This prevents idle workers from being misclassified as dead.
