# Phase 6J-B: Production Runtime Cutover

## Runtime Architecture & Dependency Injection

The Aegivion security engine leverages a centralized `PersistenceContainer` (via `packages/security/engine/config.py`) to inject stateful persistence components into the runtime. `AgentController` directly consumes this container and routes individual repositories (such as `EventStore`, `DetectionContextRepository`, and `AttackStateRepository`) to the respective `AsyncQueueWorker` instances.

The engine components (Detectors, Activation Engine, Optimizers, Execution Orchestrator) are intentionally kept persistence-agnostic. Workers are the boundary layers responsible for delegating state updates back to PostgreSQL (when running in production) or InMemory persistence (during local development).

## Environment Modes & Backend Selection

Environment modes map exclusively to the selection logic housed in `get_persistence_components()`:

- **Local Development / Test** (`ENVIRONMENT=development`, `PERSISTENCE_BACKEND=memory`): Uses `InMemoryEventStore`. Repositories are skipped for full state-loss memory runs.
- **Production PostgreSQL** (`ENVIRONMENT=production`, `PERSISTENCE_BACKEND=postgres`): Uses `PostgresEventStore` and dedicated SQLAlchemy repositories.

### Fail-Closed Behavior
In production (`ENVIRONMENT=production`), the system is designed to **fail closed**. It will aggressively halt startup (`ValueError`) if:
1. `PERSISTENCE_BACKEND` is not explicitly set to `postgres`.
2. `DATABASE_URL` is missing.
3. The SQLAlchemy connection factory fails to instantiate due to malformed URLs.

It will **never** silently fall back to `InMemoryEventStore` during a production deployment, ensuring events are never falsely acknowledged as durable when PostgreSQL is unavailable.

## Startup & Shutdown Behavior

- **Startup**: When PostgreSQL is selected, the SQLAlchemy async engine and session makers are initialized with a connection pool. Database schemas (`Base.metadata.create_all`) are intentionally omitted from runtime startup to avoid destructive changes on production clusters.
- **Shutdown**: The `PersistenceContainer` exposes a `shutdown()` routine that safely disposes of the SQLAlchemy async engine connections. The `AgentController` manages graceful draining of `AsyncQueueWorker` threads before invoking this shutdown hook.

## Connection Pool & Observability

SQLAlchemy connection pooling is configured with conservative and resilient defaults to ensure stability under load:
- `pool_size`: 10
- `max_overflow`: 20
- `pool_timeout`: 30
- `pool_recycle`: 1800 (30 minutes)

Log statements safely output:
`persistence backend = postgres`
They deliberately mask the `DATABASE_URL` and suppress raw database errors containing query literals from frontend exposure.

## Crash Recovery, Tenant Isolation & Approvals

Because the runtime delegates directly to the implementations finalized in **Phase 6J-A**, the following characteristics apply seamlessly to production:

- **Crash Recovery**: `SELECT ... FOR UPDATE SKIP LOCKED` combined with the `lease_expires_at` logic enables native crash-recovery without polling locks. Workers claiming expired records immediately re-process tasks.
- **Tenant Isolation**: Handled atomically. Multi-tenant instances using `event_id` and `org_id` as composite primary keys prevent boundary leaks.
- **Approval Workflow**: No pipeline modifications were made. The Human Approval stage relies on Phase 6I Execution verification rules which operate completely downstream of the event store's atomic event ingestion loop.

## Migration Sequence

1. Deploy migration using Alembic (`alembic upgrade head`).
2. Verify migrations applied via DB schema inspection.
3. Supply `DATABASE_URL`, `ENVIRONMENT=production`, and `PERSISTENCE_BACKEND=postgres` to task definition.
4. Start Agent Runtime. The application connects and accepts traffic.

## Testing & Known Limitations

- **Focused Tests**: Passed successfully in `packages/backend/tests/part2/test_production_runtime_cutover.py` focusing purely on DI and failure scenarios.
- **Limitations**: Full E2E tests containing legacy imports (e.g., `packages/backend/security` shadowing `packages/security`) may yield collection errors under the current `PYTHONPATH`. This does not impact runtime execution but obscures full automated pipeline runs locally.
