import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field

class AttackState(str, Enum):
    NO_ACTIVITY = "NO_ACTIVITY"
    POTENTIAL = "POTENTIAL"
    ACTIVATING = "ACTIVATING"
    ACTIVE = "ACTIVE"
    CONTAINED = "CONTAINED"
    VERIFIED_RESOLVED = "VERIFIED_RESOLVED"

class AttackStateTransition(BaseModel):
    from_state: AttackState
    to_state: AttackState
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = None

class AttackSequenceContext(BaseModel):
    org_id: str
    sequence_id: str  # Usually mapped to correlation_id or a root detection
    current_state: AttackState = AttackState.NO_ACTIVITY
    transitions: List[AttackStateTransition] = Field(default_factory=list)
    risk_score: float = 0.0
    activation_score: float = 0.0
    temporal_score: float = 0.0
    next_stage_predictions: List[Dict[str, Any]] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SecurityAttackStateTracker:
    def __init__(self):
        # Maps org_id -> sequence_id -> AttackSequenceContext
        self._contexts: Dict[str, Dict[str, AttackSequenceContext]] = {}

    def _get_or_create_context(self, org_id: str, sequence_id: str) -> AttackSequenceContext:
        if org_id not in self._contexts:
            self._contexts[org_id] = {}
        if sequence_id not in self._contexts[org_id]:
            self._contexts[org_id][sequence_id] = AttackSequenceContext(
                org_id=org_id, 
                sequence_id=sequence_id
            )
        return self._contexts[org_id][sequence_id]

    def _determine_new_state(self, temporal_score: float, risk_score: float, activation_score: float) -> AttackState:
        # A simple state machine logic based on scores
        # We assume containment/resolution are set externally by Response workers, so we only handle escalation here
        
        # If the attack is already active, we don't automatically downgrade unless we get resolution signals
        # But this function just determines the baseline state from current scores.
        if activation_score >= 0.8:
            return AttackState.ACTIVE
        elif activation_score >= 0.5 or (temporal_score >= 0.5 and risk_score >= 0.5):
            return AttackState.ACTIVATING
        elif activation_score > 0.1 or temporal_score > 0.1 or risk_score > 0.1:
            return AttackState.POTENTIAL
        else:
            return AttackState.NO_ACTIVITY

    def update_state(
        self, 
        org_id: str, 
        sequence_id: str, 
        temporal_score: float, 
        risk_score: float, 
        activation_score: float,
        predictions: List[Dict[str, Any]]
    ) -> AttackSequenceContext:
        ctx = self._get_or_create_context(org_id, sequence_id)
        
        # We only escalate state automatically. Downgrades to CONTAINED or VERIFIED_RESOLVED are done explicitly elsewhere.
        if ctx.current_state in [AttackState.CONTAINED, AttackState.VERIFIED_RESOLVED]:
            # Do not escalate if contained/resolved, wait for new sequence or explicit reopen
            pass
        else:
            proposed_state = self._determine_new_state(temporal_score, risk_score, activation_score)
            
            # Allow escalation
            state_order = {
                AttackState.NO_ACTIVITY: 0,
                AttackState.POTENTIAL: 1,
                AttackState.ACTIVATING: 2,
                AttackState.ACTIVE: 3
            }
            
            if state_order.get(proposed_state, 0) > state_order.get(ctx.current_state, 0):
                reason = f"Scores updated: T={temporal_score:.2f} R={risk_score:.2f} A={activation_score:.2f}"
                transition = AttackStateTransition(
                    from_state=ctx.current_state,
                    to_state=proposed_state,
                    reason=reason,
                    correlation_id=sequence_id
                )
                ctx.transitions.append(transition)
                ctx.current_state = proposed_state

        ctx.temporal_score = temporal_score
        ctx.risk_score = risk_score
        ctx.activation_score = activation_score
        ctx.next_stage_predictions = predictions
        ctx.last_updated = datetime.now(timezone.utc)

        return ctx

    def mark_contained(self, org_id: str, sequence_id: str, reason: str):
        ctx = self._get_or_create_context(org_id, sequence_id)
        transition = AttackStateTransition(
            from_state=ctx.current_state,
            to_state=AttackState.CONTAINED,
            reason=reason,
            correlation_id=sequence_id
        )
        ctx.transitions.append(transition)
        ctx.current_state = AttackState.CONTAINED
        ctx.last_updated = datetime.now(timezone.utc)
        return ctx

    def mark_resolved(self, org_id: str, sequence_id: str, reason: str):
        ctx = self._get_or_create_context(org_id, sequence_id)
        transition = AttackStateTransition(
            from_state=ctx.current_state,
            to_state=AttackState.VERIFIED_RESOLVED,
            reason=reason,
            correlation_id=sequence_id
        )
        ctx.transitions.append(transition)
        ctx.current_state = AttackState.VERIFIED_RESOLVED
        ctx.last_updated = datetime.now(timezone.utc)
        return ctx

    def get_context(self, org_id: str, sequence_id: str) -> Optional[AttackSequenceContext]:
        return self._contexts.get(org_id, {}).get(sequence_id)
