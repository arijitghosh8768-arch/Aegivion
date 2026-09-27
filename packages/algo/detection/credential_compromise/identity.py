"""Identity resolution: raw CloudTrail ``userIdentity`` -> :class:`ResolvedIdentity`.

The resolver answers three questions that everything downstream depends on:

1. **Who is the actor?** (``principal_id``) - for assumed roles this is the
   *role*, not the ephemeral session, so role behaviour accumulates on one key.
2. **What kind of actor is it?** (``identity_kind``) - human, federated, service
   or machine. Machine identities are never compared against human ones.
3. **Which baseline bucket does it belong to?** (``baseline_category``).

An event that cannot be attributed to a resolvable identity raises
:class:`IdentityResolutionError` rather than being dropped silently.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from .exceptions import IdentityResolutionError
from .schemas import (
    BaselineCategory,
    CloudProvider,
    IdentityKind,
    PrincipalType,
    ResolvedIdentity,
)

#: Session-name prefixes that indicate an AWS-managed / service-driven session.
_SERVICE_SESSION_PREFIXES = ("AWSServiceRoleFor", "aws-service-role", "AWSService")


class IdentityResolver:
    """Turns CloudTrail identity blocks into stable, baseline-able handles."""

    def __init__(self, *, provider: CloudProvider = CloudProvider.AWS) -> None:
        self.provider = provider

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def resolve(
        self,
        user_identity: Mapping[str, Any],
        *,
        account_id: Optional[str] = None,
        invoked_by: Optional[str] = None,
        session_issuer_role_hint: Optional[str] = None,
    ) -> ResolvedIdentity:
        """Resolve a CloudTrail ``userIdentity`` mapping.

        ``invoked_by`` is the top-level CloudTrail field used for AWS service
        principals; ``session_issuer_role_hint`` lets callers (or tests) pin a
        role ARN when the payload omits ``sessionContext``.
        """
        if not isinstance(user_identity, Mapping):
            raise IdentityResolutionError(
                "userIdentity is not an object", context={"got": type(user_identity).__name__}
            )

        raw_type = str(user_identity.get("type") or "Unknown")
        resolved_account = (
            user_identity.get("accountId")
            or account_id
            or self._account_from_arn(user_identity.get("arn"))
        )

        handler = {
            PrincipalType.IAM_USER.value: self._resolve_iam_user,
            PrincipalType.ASSUMED_ROLE.value: self._resolve_assumed_role,
            PrincipalType.ROOT.value: self._resolve_root,
            PrincipalType.FEDERATED_USER.value: self._resolve_federated_user,
            PrincipalType.AWS_SERVICE.value: self._resolve_aws_service,
            PrincipalType.SERVICE_ACCOUNT.value: self._resolve_service_account,
        }.get(raw_type)

        if handler is None:
            return self._resolve_unknown(user_identity, raw_type, resolved_account)

        return handler(
            user_identity,
            raw_type=raw_type,
            account_id=resolved_account,
            invoked_by=invoked_by,
            role_hint=session_issuer_role_hint,
        )

    # ------------------------------------------------------------------ #
    # Per-type resolvers
    # ------------------------------------------------------------------ #

    def _resolve_iam_user(
        self, ui: Mapping[str, Any], **kw: Any
    ) -> ResolvedIdentity:
        name = ui.get("userName")
        principal_id = ui.get("arn") or self._arn("user", name, kw.get("account_id"))
        if not principal_id:
            raise IdentityResolutionError(
                "IAMUser identity has neither arn nor userName",
                context={"keys": sorted(ui.keys())},
            )
        return self._build(
            principal_id=principal_id,
            principal_name=name,
            principal_type=PrincipalType.IAM_USER,
            identity_kind=IdentityKind.HUMAN,
            baseline_category=BaselineCategory.HUMAN_USER,
            account_id=kw.get("account_id"),
            raw_type=kw["raw_type"],
            session_id=ui.get("accessKeyId") or None,
            role_arn=None,
            is_human_session=True,
        )

    def _resolve_assumed_role(self, ui: Mapping[str, Any], **kw: Any) -> ResolvedIdentity:
        session_context = ui.get("sessionContext") or {}
        federation = session_context.get("webIdFederationData") or {}
        issuer = session_context.get("sessionIssuer") or {}
        attributes = session_context.get("attributes") or {}

        role_arn = issuer.get("arn") or kw.get("role_hint")
        session_arn = ui.get("arn")
        session_name = self._session_name_from_arn(session_arn) or ui.get("principalId")

        # Federated (SAML / OIDC / web identity) assumption of a role.
        # The role is the stable baseline anchor; the ephemeral session ARN is
        # recorded separately so sessions stay distinguishable.
        if federation:
            principal_id = role_arn or session_arn
            if not principal_id:
                raise IdentityResolutionError("federated assumed-role identity has no arn")
            return self._build(
                principal_id=principal_id,
                principal_name=session_name,
                principal_type=PrincipalType.FEDERATED_USER,
                identity_kind=IdentityKind.FEDERATED,
                baseline_category=BaselineCategory.FEDERATED_IDENTITY,
                account_id=kw.get("account_id"),
                raw_type=kw["raw_type"],
                session_id=session_arn,
                role_arn=role_arn,
                is_human_session=True,
            )

        # Baseline accumulates on the *role* so short-lived sessions roll up.
        principal_id = role_arn or session_arn
        if not principal_id:
            raise IdentityResolutionError(
                "AssumedRole identity has neither sessionIssuer.arn nor arn",
                context={"keys": sorted(ui.keys())},
            )

        is_service_role = self._looks_like_service_session(session_name, role_arn)
        mfa_authenticated = self._mfa_flag(attributes)

        return self._build(
            principal_id=principal_id,
            principal_name=session_name,
            principal_type=PrincipalType.ASSUMED_ROLE,
            identity_kind=IdentityKind.SERVICE if is_service_role else IdentityKind.HUMAN,
            baseline_category=(
                BaselineCategory.SERVICE_IDENTITY
                if is_service_role
                else BaselineCategory.ASSUMED_ROLE
            ),
            account_id=kw.get("account_id"),
            raw_type=kw["raw_type"],
            session_id=session_arn,
            role_arn=role_arn,
            is_human_session=bool(mfa_authenticated) or not is_service_role,
        )

    def _resolve_root(self, ui: Mapping[str, Any], **kw: Any) -> ResolvedIdentity:
        account = kw.get("account_id")
        principal_id = ui.get("arn") or (
            f"arn:aws:iam::{account}:root" if account else "root"
        )
        return self._build(
            principal_id=principal_id,
            principal_name="root",
            principal_type=PrincipalType.ROOT,
            identity_kind=IdentityKind.HUMAN,
            baseline_category=BaselineCategory.HUMAN_USER,
            account_id=account,
            raw_type=kw["raw_type"],
            session_id=ui.get("accessKeyId") or None,
            role_arn=None,
            is_human_session=True,
        )

    def _resolve_federated_user(self, ui: Mapping[str, Any], **kw: Any) -> ResolvedIdentity:
        principal_id = ui.get("arn") or ui.get("principalId")
        if not principal_id:
            raise IdentityResolutionError("FederatedUser identity has no arn or principalId")
        return self._build(
            principal_id=principal_id,
            principal_name=ui.get("userName") or ui.get("principalId"),
            principal_type=PrincipalType.FEDERATED_USER,
            identity_kind=IdentityKind.FEDERATED,
            baseline_category=BaselineCategory.FEDERATED_IDENTITY,
            account_id=kw.get("account_id"),
            raw_type=kw["raw_type"],
            session_id=ui.get("accessKeyId") or None,
            role_arn=None,
            is_human_session=True,
        )

    def _resolve_aws_service(self, ui: Mapping[str, Any], **kw: Any) -> ResolvedIdentity:
        invoked_by = kw.get("invoked_by") or ui.get("invokedBy") or "unknown-service"
        principal_id = f"aws-service:{invoked_by}"
        return self._build(
            principal_id=principal_id,
            principal_name=invoked_by,
            principal_type=PrincipalType.AWS_SERVICE,
            identity_kind=IdentityKind.SERVICE,
            baseline_category=BaselineCategory.SERVICE_IDENTITY,
            account_id=kw.get("account_id"),
            raw_type=kw["raw_type"],
            session_id=None,
            role_arn=None,
            is_human_session=False,
        )

    def _resolve_service_account(self, ui: Mapping[str, Any], **kw: Any) -> ResolvedIdentity:
        principal_id = ui.get("arn") or ui.get("principalId")
        if not principal_id:
            raise IdentityResolutionError("ServiceAccount identity has no arn or principalId")
        return self._build(
            principal_id=principal_id,
            principal_name=ui.get("userName"),
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            identity_kind=IdentityKind.MACHINE,
            baseline_category=BaselineCategory.MACHINE_IDENTITY,
            account_id=kw.get("account_id"),
            raw_type=kw["raw_type"],
            session_id=ui.get("accessKeyId") or None,
            role_arn=None,
            is_human_session=False,
        )

    def _resolve_unknown(
        self, ui: Mapping[str, Any], raw_type: str, account_id: Optional[str]
    ) -> ResolvedIdentity:
        """Unknown types are treated conservatively as machine identities.

        They are *not* rejected outright, but they get their own baseline
        category so they can never pollute a human baseline.
        """
        principal_id = ui.get("arn") or ui.get("principalId") or ui.get("userName")
        if not principal_id:
            raise IdentityResolutionError(
                "cannot resolve identity: no arn, principalId or userName",
                context={"type": raw_type, "keys": sorted(ui.keys())},
            )
        return self._build(
            principal_id=str(principal_id),
            principal_name=ui.get("userName"),
            principal_type=PrincipalType.UNKNOWN,
            identity_kind=IdentityKind.UNKNOWN,
            baseline_category=BaselineCategory.UNKNOWN,
            account_id=account_id,
            raw_type=raw_type,
            session_id=None,
            role_arn=None,
            is_human_session=False,
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _build(
        self,
        *,
        principal_id: str,
        principal_name: Optional[str],
        principal_type: PrincipalType,
        identity_kind: IdentityKind,
        baseline_category: BaselineCategory,
        account_id: Optional[str],
        raw_type: Optional[str],
        session_id: Optional[str],
        role_arn: Optional[str],
        is_human_session: bool,
    ) -> ResolvedIdentity:
        identity_key = self.identity_key(
            provider=self.provider,
            account_id=account_id,
            baseline_category=baseline_category,
            principal_id=principal_id,
        )
        return ResolvedIdentity(
            identity_key=identity_key,
            provider=self.provider,
            account_id=account_id,
            principal_id=principal_id,
            principal_name=principal_name,
            principal_type=principal_type,
            identity_kind=identity_kind,
            baseline_category=baseline_category,
            role_arn=role_arn,
            session_id=session_id,
            is_human_session=is_human_session,
            raw_type=raw_type,
        )

    @staticmethod
    def identity_key(
        *,
        provider: CloudProvider,
        account_id: Optional[str],
        baseline_category: BaselineCategory,
        principal_id: str,
    ) -> str:
        """Canonical baseline key: provider:account:category:principal."""
        account = account_id or "noaccount"
        return f"{provider.value}:{account}:{baseline_category.value}:{principal_id}"

    @staticmethod
    def _session_name_from_arn(arn: Optional[str]) -> Optional[str]:
        if not arn:
            return None
        return arn.rsplit("/", 1)[-1] or None

    @staticmethod
    def _account_from_arn(arn: Optional[str]) -> Optional[str]:
        if not arn or not arn.startswith("arn:"):
            return None
        parts = arn.split(":")
        if len(parts) >= 5 and parts[4]:
            return parts[4]
        return None

    @staticmethod
    def _arn(resource: str, name: Optional[str], account: Optional[str]) -> Optional[str]:
        if not name:
            return None
        account_part = account or "*"
        return f"arn:aws:iam::{account_part}:{resource}/{name}"

    @staticmethod
    def _mfa_flag(attributes: Mapping[str, Any]) -> Optional[bool]:
        raw = attributes.get("mfaAuthenticated")
        if raw is None:
            return None
        return str(raw).strip().lower() == "true"

    @staticmethod
    def _looks_like_service_session(
        session_name: Optional[str], role_arn: Optional[str]
    ) -> bool:
        haystack = f"{session_name or ''} {role_arn or ''}"
        return any(hint.lower() in haystack.lower() for hint in _SERVICE_SESSION_PREFIXES)


__all__ = ["IdentityResolver"]
