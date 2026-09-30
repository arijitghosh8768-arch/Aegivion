# Phase 6H-2G: Distributed Health

## 1. Worker Identity
Each worker has a typed `WorkerIdentity` encompassing:
- `node_id`: Host or logical node grouping the worker
- `worker_id`: Unique worker instance ID
- `worker_type`: Type of worker (e.g. EVENT_INGESTION, DETECTION_CORRELATION)
- `state`: Current health classification
- Operational metrics (queue depth, counts, restarts)

## 2. Heartbeat Mechanism
Workers register upon starting (`register_worker`) and emit periodic heartbeats (`heartbeat`) via the `WorkerHealthRepository` abstraction. Heartbeats include health/state updates and lightweight metrics (queue depth, events processed).
No credentials, cloud secrets, or raw payloads are ever transmitted via heartbeat.

## 3. Stale Detection
The `DistributedHealthMonitor` checks worker timestamps against a logical `Clock`. Workers whose `last_heartbeat` exceeds a configured timeout (e.g., 15 seconds) are transitioned to `STALE`.
A stale worker is not deleted. If it resumes heartbeating, it transitions back to `HEALTHY`.

## 4. Node Health & Cluster Health
Node health aggregates all workers for a specific `node_id`. If a node loses all its workers, or they become `STALE`/`FAILED`, the node is `FAILED`.
Cluster health is determined by critical capacity. For example, if all `EVENT_INGESTION` workers fail, the cluster is `FAILED`. If only 1 out of N fails, it may remain `DEGRADED` but operational.

## 5. Capacity Calculation & Queue Health
Health is capacity-aware, tracking `queue_capacity`, `queue_depth`, and `queue_utilization`. Utilization above 90% transitions cluster health to `DEGRADED` due to pressure.

## 6. Recovery Integration
Distributed health provides observability. A failed or stale worker could be restarted by an `AgentRecoveryManager`.

## 7. Lease and Fencing Interaction
Worker health and event leases are strictly separated. 
A `HEALTHY` worker does not automatically own events (it still needs a lease). 
A `STALE` worker does not instantly forfeit an event (the lease must expire first). 
The fencing mechanism remains authoritative. Health monitoring NEVER forcibly revokes an active lease or modifies a fencing token.

## 8. Tenant Isolation & Security Boundaries
Health metrics are aggregated at the worker level. No tenant-specific payloads or credentials are included in distributed health snapshots. Health systems do not make security determinations, invoke cloud APIs, or score risk.

## 9. Limitations & Persistence
The current implementation uses an `InMemoryWorkerHealthRepository` to validate the distributed health semantics. For production, an external durable storage backend (like Redis or PostgreSQL) is required.
