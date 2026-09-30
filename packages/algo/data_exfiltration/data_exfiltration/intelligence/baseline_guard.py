"""Baseline poisoning protection.

Trusted baselines must not silently absorb attacker behavior. Policy:

- LOW risk activity  -> eligible to update trusted baselines
- MEDIUM risk        -> limited influence (recorded for audit, excluded
                        from trusted percentile statistics)
- HIGH risk          -> never updates trusted baselines automatically

An analyst override can later promote audited observations; automatic
learning cannot.
"""

from __future__ import annotations

from enum import Enum


class BaselineInfluence(str, Enum):
    ELIGIBLE = "eligible"
    LIMITED = "limited"
    BLOCKED = "blocked"


class BaselinePoisoningPolicy:
    """Risk-gated eligibility for baseline updates."""

    def __init__(
        self,
        medium_influence: BaselineInfluence = BaselineInfluence.LIMITED,
        high_influence: BaselineInfluence = BaselineInfluence.BLOCKED,
    ) -> None:
        self._policy = {
            "low": BaselineInfluence.ELIGIBLE,
            "medium": medium_influence,
            "high": high_influence,
        }

    def influence_for(self, risk: str) -> BaselineInfluence:
        """Map a risk label to baseline-update influence.

        Unknown risk labels are treated conservatively as LIMITED: they
        are recorded for audit but cannot shape trusted statistics.
        """
        return self._policy.get(str(risk).lower(), BaselineInfluence.LIMITED)

    def can_shape_trusted(self, risk: str) -> bool:
        return self.influence_for(risk) is BaselineInfluence.ELIGIBLE
