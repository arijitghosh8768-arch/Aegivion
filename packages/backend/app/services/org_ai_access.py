"""Scoped lookup of an organization's AI feature setting.

Why this module exists
----------------------
``app.models.org_settings.OrgSettings`` inherits ``LegacyBaseModel``, a
metaclass-backed stand-in that is **not** a SQLAlchemy mapped class (it has no
``__table__`` and attributes such as ``OrgSettings.organization_id`` are
``MockField`` objects). Passing it to ``Session.query()`` raises
``ArgumentError``, which made ``/api/v1/ai/chat`` and ``/api/v1/explain/{id}``
fail before any AI work happened. There is also no ``org_settings`` table in any
database this project ships.

This module reads the setting from the mapped ``organizations`` row instead
(``organizations.settings['ai_features_enabled']``), which requires no schema
change.

Authorization semantics (deliberately unchanged)
------------------------------------------------
The previous check was ``if settings and not settings.ai_features_enabled``.

* An explicit ``false`` disables AI for that organization.
* No organization row, or no explicit flag, leaves AI enabled - exactly as
  before, when the absence of a settings record meant "no restriction".
* A tenant identifier that cannot be resolved is treated as **denied**
  (fail-closed), because such a caller cannot be matched to any organization.
* Lookup errors are *not* swallowed: they propagate so the request fails
  rather than silently granting access.

This module performs no authentication and no membership checks; those remain
where they already were. It only answers "is AI allowed for this org".
"""

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from app.models.organization import Organization

logger = logging.getLogger(__name__)

AI_FEATURE_SETTING_KEY = "ai_features_enabled"


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None or isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def is_ai_enabled_for_organization(db: Session, organization_id: Any) -> bool:
    """Return ``True`` when the organization may use AI features.

    A tenant identifier that cannot be resolved against the ``uuid`` primary key
    is **denied** rather than allowed, and lookup errors are never converted
    into "enabled".
    """
    if organization_id is None or organization_id == "":
        # No tenant context at all: deny.
        logger.warning("AI access denied: missing organization identifier")
        return False

    org_uuid = _coerce_uuid(organization_id)
    query_value = org_uuid if org_uuid is not None else str(organization_id)

    try:
        organization = (
            db.query(Organization).filter(Organization.id == query_value).first()
        )
    except StatementError as exc:
        # The identifier cannot be represented by the uuid column, so no
        # settings record can exist for it: deny instead of allowing.
        logger.warning(
            "AI access denied: unusable organization identifier %r (%s)",
            organization_id,
            exc,
        )
        return False

    if organization is None:
        # Preserved behaviour: no stored settings means no AI restriction.
        return True

    settings = organization.settings
    if not isinstance(settings, dict):
        return True

    return bool(settings.get(AI_FEATURE_SETTING_KEY, True))
