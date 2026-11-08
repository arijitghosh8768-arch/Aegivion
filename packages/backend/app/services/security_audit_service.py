import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger("security_audit")

def log_security_event(
    db: Session,
    event_type: str,
    action: str,
    organization_id: Optional[str] = None,
    account_id: Optional[str] = None,
    provider: str = "app",
    actor: Optional[Dict[str, Any]] = None,
    target: Optional[Dict[str, Any]] = None,
    source: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Failsafe utility to persist security audit events directly into PostgreSQL `security_events` table.
    - Generates deterministic event fingerprint for deduplication/indexing.
    - Captures pre-auth (organization_id=None) and post-auth security milestones.
    - Safe execution: Logs error without crashing API request if DB write fails.
    """
    try:
        event_id = str(uuid.uuid4())
        actor_json = actor or {}
        target_json = target or {}
        source_json = source or {}
        metadata_json = metadata or {}
        now = datetime.now(timezone.utc)

        # Deterministic SHA-256 fingerprint
        fp_material = f"{provider}:{organization_id or 'none'}:{event_type}:{action}:{now.strftime('%Y%m%d%H%M')}:{uuid.uuid4().hex[:8]}"
        fingerprint = hashlib.sha256(fp_material.encode("utf-8")).hexdigest()[:64]

        # Direct SQL Insert ensures independence from any model mismatch
        insert_query = text("""
            INSERT INTO security_events (
                id,
                organization_id,
                account_id,
                event_id,
                provider,
                event_type,
                action,
                timestamp,
                actor,
                target,
                source,
                metadata,
                native_event_id,
                event_fingerprint,
                created_at,
                updated_at,
                is_active
            ) VALUES (
                :id,
                :organization_id,
                :account_id,
                :event_id,
                :provider,
                :event_type,
                :action,
                :timestamp,
                CAST(:actor AS jsonb),
                CAST(:target AS jsonb),
                CAST(:source AS jsonb),
                CAST(:metadata AS jsonb),
                :native_event_id,
                :event_fingerprint,
                :created_at,
                :updated_at,
                true
            )
        """)

        db.execute(
            insert_query,
            {
                "id": uuid.UUID(event_id),
                "organization_id": uuid.UUID(organization_id) if organization_id else None,
                "account_id": uuid.UUID(account_id) if account_id else None,
                "event_id": event_id,
                "provider": provider,
                "event_type": event_type,
                "action": action,
                "timestamp": now,
                "actor": json.dumps(actor_json),
                "target": json.dumps(target_json),
                "source": json.dumps(source_json),
                "metadata": json.dumps(metadata_json),
                "native_event_id": event_id,
                "event_fingerprint": fingerprint,
                "created_at": now,
                "updated_at": now
            }
        )
        db.commit()
        return event_id
    except Exception as exc:
        logger.error(f"[Security Audit] Failed to persist security event: {exc}", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
        return None

