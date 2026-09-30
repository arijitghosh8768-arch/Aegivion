from typing import Dict, Any
from app.repositories.security_event_repository import SecurityEventRepository
from security.engine.normalizers.aws import AWSNormalizer
from security.engine.normalizers.azure import AzureNormalizer
from security.engine.normalizers.gcp import GCPNormalizer
from security.engine.security_digital_twin import SecurityDigitalTwin
from app.models.security_event import SecurityEvent

class SecurityEventIngestionService:
    def __init__(self, db_client, db_session, agent_controller=None):
        self.event_repo = SecurityEventRepository(db_client)
        self.db_session = db_session
        self.agent_controller = agent_controller

    async def ingest(self, raw_event: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        organization_id = context.get("organization_id")
        provider = context.get("provider", "").lower()

        if not organization_id:
            return {"status": "rejected", "reason": "Missing trusted organization context"}

        # Normalize
        try:
            if provider == "aws":
                canonical_event = AWSNormalizer.normalize(raw_event, context)
            elif provider == "azure":
                canonical_event = AzureNormalizer.normalize(raw_event, context)
            elif provider == "gcp":
                canonical_event = GCPNormalizer.normalize(raw_event, context)
            else:
                return {"status": "rejected", "reason": f"Unknown provider: {provider}"}
        except Exception as e:
            return {"status": "failed", "reason": f"Normalization failed: {str(e)}"}

        # Deduplicate
        if self.event_repo.check_duplicate(organization_id, canonical_event.event_fingerprint):
            return {
                "status": "duplicate",
                "event_id": canonical_event.event_id,
                "fingerprint": canonical_event.event_fingerprint,
                "organization_id": organization_id,
                "provider": provider,
                "reason": "Duplicate event ignored"
            }

        # Persist
        try:
            self.event_repo.create(canonical_event)
        except Exception as e:
            return {"status": "failed", "reason": f"Persistence failed: {str(e)}"}

        # Digital Twin Update
        try:
            twin = SecurityDigitalTwin(self.db_session, organization_id)
            twin.update_from_event(canonical_event)
        except Exception as e:
            return {"status": "failed", "reason": f"Digital Twin update failed: {str(e)}"}

        # Submit to AgentController
        if self.agent_controller:
            from security.engine.agent_controller import AgentEvent, EventSource
            agent_event = AgentEvent(
                event_id=canonical_event.event_id,
                organization_id=organization_id,
                event_type="CLOUD_EVENT",
                occurred_at=canonical_event.timestamp,
                source=EventSource.CLOUD,
                correlation_id="",
                payload=canonical_event.dict(),
            )
            submission_status = await self.agent_controller.submit_event(agent_event)
            if submission_status not in ("ACCEPTED", "DUPLICATE_EVENT"):
                return {"status": "failed", "reason": f"AgentController rejected: {submission_status}"}

        return {
            "status": "stored",
            "event_id": canonical_event.event_id,
            "fingerprint": canonical_event.event_fingerprint,
            "organization_id": organization_id,
            "provider": provider,
            "reason": "Successfully processed"
        }
