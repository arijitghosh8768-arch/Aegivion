# Phase 6H-2F: Crash Recovery & Controlled Reprocessing

## Overview
The `CrashRecoveryManager` provides mechanisms for detecting node/worker failures, recovering stale workers, explicitly handling dead-letter requeueing, and controlling startup recovery. It operates on top of the distributed health monitoring and persistent event tracking infrastructure.

## Key Principles
1. **No Automatic Resurrection of `DEAD_LETTER` events:** Events that exceed max retries or hit a fatal error enter the `DEAD_LETTER` state. The CrashRecoveryManager exposes `requeue_dead_letter` for manual or controlled intervention by an administrator, which logs a `RequeueRecord` tracking the requeue reason and requesting user.
2. **Lease Authority:** Worker crashes are identified via `HealthState.STALE`, but ownership of events is ONLY broken when their `lease_expires_at` has passed. Zombie workers will have their leases naturally expire and all subsequent mutations via their stale fencing tokens will be atomically rejected by the `EventStore`.
3. **Poison Message Loop Prevention:** Explicit requeue operations decrement against a maximum `requeue_count` boundary. Events surpassing the maximum requeues can never leave `DEAD_LETTER`.
4. **Startup Recovery:** When the system starts, it relies exclusively on persistent state. Previous in-memory worker references are discarded. Extant events with expired leases seamlessly transition back into the `CLAIMABLE` pool for newly spun-up workers to process.

## Worker Crash Handling
* **Stale Detection:** Uses `DistributedHealthMonitor` to inspect heartbeats.
* **Worker Restart:** Stale local workers invoke `AgentRecoveryManager.attempt_restart()` which uses a circuit breaker and exponential backoff to revive the worker process safely.
* **Zombie Mitigations:** Fencing tokens guarantee that an ungracefully restarted worker cannot execute stale tasks or commit mutations from a pre-crash state.

## Tenant Isolation
All recovery and requeue actions strictly enforce multi-tenant separation. Requeueing an event targets `(org_id, event_id)` protecting against cross-tenant data corruption.
