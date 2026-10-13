# Event and Data Contracts

## Event requirements
Normalize provider events into a canonical schema with provider/source identifiers, event and ingestion times, tenant scope, actor, action, resource references, and provenance when available. Deduplicate with a stable fingerprint. Make state transitions explicit and auditable. Use idempotent processing, bounded retries, persistent dead-letter state, and explicit authorized/audited requeue.

Missing data is not proof that an event did not occur.

## Evidence labels
- **Observed:** directly present in source event, configuration, or verified state.
- **Inferred:** computed from observed evidence using documented logic.
- **Unknown:** unavailable, contradictory, stale, or insufficiently supported.

## Asset and relationship requirements
Assets should identify provider, provider-native ID, canonical type, account/project/subscription, region, tenant, configuration, timestamps/version, and relationships. Relationships need source, target, type, provenance, observation time, and confidence when applicable.

## Versioning
Schema changes require compatibility analysis, migration strategy, tests, and documentation updates.
