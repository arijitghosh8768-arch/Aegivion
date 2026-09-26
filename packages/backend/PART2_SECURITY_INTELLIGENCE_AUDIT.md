# Aegivion Part 2 — Security Intelligence Audit

## Existing Security Digital Twin Components

### Existing
- **CloudAsset**: SQLAlchemy model representing the foundational cloud resources.
- **AssetRelationship**: SQLAlchemy model mapping connections between assets.
- **SecurityContext**: Python object (`app.cloud.aws.context.asset_context.py`) used to build security context, determine exposure, and evaluate blast radius.
- **RelationshipEngine**: AWS-specific engine (`app.cloud.aws.relationships.engine.py`) that builds network, identity, and storage relationships based on asset configurations.
- **AIContextAggregator**: Service (`test_pipeline.py` references `AIContextAggregator.build_context`) that synthesizes finding/asset context.

### Partially Implemented
- The connection between SecurityContext and real-time events. Currently, relationships are built on scan (orchestrator), but not dynamically maintained as a "living" twin.
- Security graph generation (`topology.py`) reads directly from `AssetRepository`, dynamically joining JSON relationships, but lacks a dedicated graph DB or twin layer.

### Missing
- A unified `SecurityDigitalTwin` entity/service that continuously maintains and exposes the real-time state of the cloud environment.
- Bi-directional event-driven updates (updating the twin when a `security_event` occurs without a full scan).

### Must Preserve
- The existing relationship schemas and standardized relationship types (`connected_to`, `protected_by`, `managed_by`, etc.).
- Tenant isolation boundaries via `get_current_organization()`.
- The current `AssetRepository` interfaces.

### Must Extend
- The digital twin needs to subscribe to or ingest `security_events` to update its state.
- Create a `SecurityDigitalTwin` abstraction that wraps the asset/relationship/context logic.

## Existing Security Event Pipeline

### Event Sources
- The `/api/v1/events` endpoint (`ingest_event`) accepts raw JSON and inserts directly into Supabase.

### Validation
- **None/Minimal**. The API route just injects the `organization_id` into the raw JSON payload and inserts it directly into the `security_events` table.

### Normalization
- **None**. The raw event data is stored as-is in the Supabase table.

### Deduplication
- **None apparent**.

### Storage
- Supabase `security_events` table (bypassing SQLAlchemy).
- Read via `SecurityEventRepository(supabase)`.

### Consumers
- Endpoint `/api/v1/events` (reads latest 50 events).
- (Pending integration with Detection Engine).

## Existing Detection Components

### Credential Compromise
- To be determined / partially implemented via AI or static rules.

### Data Exfiltration
- To be determined / partially implemented.

### Ransomware / Destruction
- To be determined / partially implemented.

## Existing Attack Path Components
- `critical_attack_paths` and `high_attack_paths` tracked in `History` models.
- Attack path algorithms exist in `security/engine/attack_paths.py` (as referenced by previous context).
- Optimization scoring uses `attack_path_reduction` (in `automation.optimizer`).

## Existing Risk Components
- `risk.py` API calculates telemetry.
- `SecurityRiskSnapshot` tracks historical risk.
- The `RiskEngine` calculates severity based on exposure and findings.

## Integration Gaps
- The event pipeline (`security_events`) is currently disconnected from the `SecurityContext` / Digital Twin. Events are just logged.
- The digital twin components (Asset, Relationship, Context) are scattered and evaluated on-demand during scans rather than persisting as an easily queryable, event-driven graph.
- No normalization or schema validation on incoming security events.

## Part 2 Step 1 Implementation Target
- Create the **Security Digital Twin data contract**. 
- Unify `CloudAsset`, `AssetRelationship`, and `SecurityContext` into a cohesive `SecurityDigitalTwin` service.
- Define a structured schema/normalization layer for `security_events`.
- Connect the event pipeline so that incoming events can update the Digital Twin state.
