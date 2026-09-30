"""Repository for the shared Aegivion ``security_findings`` table.

The detector does not own a private findings store: Part 2's ``finding.py``
builds a :class:`FindingRecord` and persists it here, so Cloud Credential
Compromise findings sit alongside every other Aegivion detector's output and can
flow through ARDE, correlation and the Explainable AI layer unchanged.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from algo.detection.credential_compromise.schemas import CloudProvider, Severity, ensure_utc

from .models import SecurityFindingRow


class FindingRecord(BaseModel):
    """Persistence-shaped finding.

    ``risk_score`` (how dangerous) and ``confidence`` (how well evidenced) are
    deliberately separate fields.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    finding_type: str = "CloudCredentialCompromise"

    identity_key: str
    provider: CloudProvider = CloudProvider.AWS
    account_id: Optional[str] = None
    principal_id: str
    principal_name: Optional[str] = None

    severity: Severity
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)

    signals: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

    session_key: Optional[str] = None
    first_seen: datetime
    last_seen: datetime

    status: str = "OPEN"
    arde_status: Optional[str] = None

    def masked_view(self) -> dict[str, Any]:
        """A log-safe summary for dashboards and the explainability layer."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "principal": self.principal_name or self.principal_id,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "signals": list(self.signals),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
        }


class SqlFindingRepository:
    """SQLAlchemy-backed findings store."""

    def __init__(self, session: OrmSession) -> None:
        self.session = session

    def save_finding(self, record: FindingRecord) -> SecurityFindingRow:
        row = self.session.execute(
            select(SecurityFindingRow).where(SecurityFindingRow.finding_id == record.finding_id)
        ).scalar_one_or_none()

        if row is None:
            row = SecurityFindingRow(finding_id=record.finding_id)
            self.session.add(row)

        row.finding_type = record.finding_type
        row.identity_key = record.identity_key
        row.provider = record.provider.value
        row.account_id = record.account_id
        row.principal_id = record.principal_id
        row.principal_name = record.principal_name
        row.severity = record.severity.value
        row.risk_score = record.risk_score
        row.confidence = record.confidence
        row.signals = list(record.signals)
        row.evidence = list(record.evidence)
        row.recommended_actions = list(record.recommended_actions)
        row.session_key = record.session_key
        row.first_seen = ensure_utc(record.first_seen)
        row.last_seen = ensure_utc(record.last_seen)
        row.status = record.status
        row.arde_status = record.arde_status

        self.session.flush()
        return row

    def get_finding(self, finding_id: str) -> Optional[FindingRecord]:
        row = self.session.execute(
            select(SecurityFindingRow).where(SecurityFindingRow.finding_id == finding_id)
        ).scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    def list_findings(
        self,
        *,
        identity_key: Optional[str] = None,
        status: Optional[str] = None,
        min_risk: Optional[float] = None,
        finding_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[FindingRecord]:
        statement = select(SecurityFindingRow)
        if identity_key:
            statement = statement.where(SecurityFindingRow.identity_key == identity_key)
        if status:
            statement = statement.where(SecurityFindingRow.status == status)
        if min_risk is not None:
            statement = statement.where(SecurityFindingRow.risk_score >= min_risk)
        if finding_type:
            statement = statement.where(SecurityFindingRow.finding_type == finding_type)
        statement = statement.order_by(SecurityFindingRow.risk_score.desc()).limit(limit)
        return [_to_domain(row) for row in self.session.execute(statement).scalars()]

    def update_status(self, finding_id: str, status: str) -> bool:
        row = self.session.execute(
            select(SecurityFindingRow).where(SecurityFindingRow.finding_id == finding_id)
        ).scalar_one_or_none()
        if row is None:
            return False
        row.status = status
        self.session.flush()
        return True

    def set_arde_status(self, finding_id: str, arde_status: str) -> bool:
        row = self.session.execute(
            select(SecurityFindingRow).where(SecurityFindingRow.finding_id == finding_id)
        ).scalar_one_or_none()
        if row is None:
            return False
        row.arde_status = arde_status
        self.session.flush()
        return True


def _to_domain(row: SecurityFindingRow) -> FindingRecord:
    return FindingRecord(
        finding_id=row.finding_id,
        finding_type=row.finding_type,
        identity_key=row.identity_key,
        provider=CloudProvider(row.provider),
        account_id=row.account_id,
        principal_id=row.principal_id,
        principal_name=row.principal_name,
        severity=Severity(row.severity),
        risk_score=row.risk_score,
        confidence=row.confidence,
        signals=list(row.signals or []),
        evidence=list(row.evidence or []),
        recommended_actions=list(row.recommended_actions or []),
        session_key=row.session_key,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        status=row.status,
        arde_status=row.arde_status,
    )


__all__ = ["FindingRecord", "SqlFindingRepository"]
