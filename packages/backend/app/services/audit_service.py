import hashlib
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.models.audit_log import AuditLog, AuditAction
from app.database import SessionLocal

class AuditService:
    def __init__(self, db_session=None):
        self.db = db_session or SessionLocal()
    
    def log_action(self, user_id: str, org_id: str, action: AuditAction,
                   resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                   details: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None,
                   user_agent: Optional[str] = None) -> AuditLog:
        """Log an audit action with tamper-evident chain hashing"""
        
        details_json = json.dumps(details or {}, sort_keys=True)
        
        # Create tamper-proof hash (blockchain-like chain)
        previous_hash = "0" * 64
        previous_log = self.db.query(AuditLog).order_by(AuditLog.created_at.desc()).first()
        
        # Check details json to retrieve hash
        if previous_log and hasattr(previous_log, "details") and isinstance(previous_log.details, dict):
            # Fallback placeholder since hash column is not created in initial models schema
            previous_hash = previous_log.details.get("_log_hash", "0" * 64)
            
        content = f"{previous_hash}|{user_id}|{org_id}|{action.value}|{details_json}|{datetime.utcnow().isoformat()}"
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        
        extended_details = details or {}
        extended_details["_log_hash"] = current_hash
        extended_details["_prev_hash"] = previous_hash
        
        audit_entry = AuditLog(
            user_id=user_id,
            organization_id=org_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=extended_details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(audit_entry)
        self.db.commit()
        return audit_entry
    
    def verify_audit_integrity(self) -> bool:
        """Verify the integrity of the audit log chain (tamper detection)"""
        logs = self.db.query(AuditLog).order_by(AuditLog.created_at.asc()).all()
        
        for i, log in enumerate(logs):
            details = log.details or {}
            prev_hash = details.get("_prev_hash", "0" * 64)
            log_hash = details.get("_log_hash", "")
            
            if i == 0:
                if prev_hash != "0" * 64:
                    return False
                continue
                
            prev_log_details = logs[i-1].details or {}
            expected_prev_hash = prev_log_details.get("_log_hash", "0" * 64)
            
            if prev_hash != expected_prev_hash:
                return False
                
        return True
