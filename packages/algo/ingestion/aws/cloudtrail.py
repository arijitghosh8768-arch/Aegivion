"""AWS CloudTrail -> :class:`IdentityActivityEvent` normalization.

This module is the only place that understands raw CloudTrail JSON. It:

1. accepts the three delivery shapes (raw record, EventBridge envelope, S3
   ``{"Records": [...]}`` file),
2. validates required fields and *never* drops a record silently,
3. resolves the acting identity via :class:`IdentityResolver`,
4. classifies the API into a family / read-write direction / privilege change,
5. attaches IP intelligence through the :class:`IpEnricher` seam,
6. emits a fully typed :class:`IdentityActivityEvent`.

Records that cannot be normalized raise :class:`MalformedEventError`; the
batch entry point quarantines them instead of guessing.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.credential_compromise.config import DetectorConfig, IngestConfig
from algo.detection.credential_compromise.exceptions import MalformedEventError
from algo.detection.credential_compromise.identity import IdentityResolver
from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    CloudProvider,
    EventCategory,
    IdentityActivityEvent,
    PRIVILEGE_MUTATION_FAMILIES,
    ensure_utc,
    normalize_ip,
)

from .enrichment import IpEnricher, NullIpEnricher

REQUIRED_RECORD_FIELDS = ("eventID", "eventTime", "eventSource", "eventName")

# --------------------------------------------------------------------------- #
# AWS API taxonomy
# --------------------------------------------------------------------------- #

#: APIs that change who can do what (privilege escalation surface).
_PRIVILEGE_MUTATION_APIS: frozenset[str] = frozenset(
    {
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "DeleteUserPolicy",
        "DeleteRolePolicy",
        "DeleteGroupPolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "DetachUserPolicy",
        "DetachRolePolicy",
        "DetachGroupPolicy",
        "CreatePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "DeletePolicy",
        "DeletePolicyVersion",
        "CreateRole",
        "DeleteRole",
        "UpdateAssumeRolePolicy",
        "AddUserToGroup",
        "RemoveUserFromGroup",
        "CreateUser",
        "DeleteUser",
        "UpdateUser",
        "AddRoleToInstanceProfile",
        "RemoveRoleFromInstanceProfile",
        "CreateInstanceProfile",
        "PutUserPermissionsBoundary",
        "DeleteUserPermissionsBoundary",
        "PutRolePermissionsBoundary",
        "DeleteRolePermissionsBoundary",
        "CreateSAMLProvider",
        "UpdateSAMLProvider",
        "CreateOpenIDConnectProvider",
        "UpdateOpenIDConnectProviderThumbprint",
    }
)

#: APIs that create, modify or remove credential material.
_CREDENTIAL_MANAGEMENT_APIS: frozenset[str] = frozenset(
    {
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateAccessKey",
        "CreateServiceSpecificCredential",
        "ResetServiceSpecificCredential",
        "DeleteServiceSpecificCredential",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "DeleteLoginProfile",
        "EnableMFADevice",
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
        "CreateVirtualMFADevice",
        "ResyncMFADevice",
        "UploadSSHPublicKey",
        "DeleteSSHPublicKey",
        "UpdateSSHPublicKey",
        "UploadSigningCertificate",
        "CreateServiceLinkedRole",
    }
)

_SECURITY_CONTROL_TAMPER: dict[str, str] = {
    # CloudTrail
    "StopLogging": ApiFamilies.CLOUDTRAIL_TAMPER,
    "DeleteTrail": ApiFamilies.CLOUDTRAIL_TAMPER,
    "UpdateTrail": ApiFamilies.CLOUDTRAIL_TAMPER,
    "PutEventSelectors": ApiFamilies.CLOUDTRAIL_TAMPER,
    # GuardDuty
    "DeleteDetector": ApiFamilies.GUARDDUTY_TAMPER,
    "UpdateDetector": ApiFamilies.GUARDDUTY_TAMPER,
    "StopMonitoringMembers": ApiFamilies.GUARDDUTY_TAMPER,
    "DisassociateFromMasterAccount": ApiFamilies.GUARDDUTY_TAMPER,
    # AWS Config
    "DeleteConfigurationRecorder": ApiFamilies.CONFIG_TAMPER,
    "StopConfigurationRecorder": ApiFamilies.CONFIG_TAMPER,
    "DeleteDeliveryChannel": ApiFamilies.CONFIG_TAMPER,
    "PutConfigurationRecorder": ApiFamilies.CONFIG_TAMPER,
}

_STS_APIS: frozenset[str] = frozenset(
    {
        "AssumeRole",
        "AssumeRoleWithSAML",
        "AssumeRoleWithWebIdentity",
        "GetSessionToken",
        "GetFederationToken",
        "GetCallerIdentity",
    }
)

_S3_READ_APIS: frozenset[str] = frozenset(
    {
        "GetObject",
        "GetObjectAcl",
        "GetObjectAttributes",
        "HeadObject",
        "ListObjects",
        "ListObjectsV2",
        "ListObjectVersions",
        "ListBuckets",
        "SelectObjectContent",
        "GetBucketLocation",
        "GetBucketPolicy",
        "GetBucketAcl",
        "ListMultipartUploads",
    }
)

_S3_WRITE_APIS: frozenset[str] = frozenset(
    {
        "PutObject",
        "DeleteObject",
        "DeleteObjects",
        "CopyObject",
        "PutObjectAcl",
        "RestoreObject",
        "AbortMultipartUpload",
        "CompleteMultipartUpload",
        "CreateMultipartUpload",
        "UploadPart",
        "PutObjectTagging",
    }
)

_S3_MANAGEMENT_APIS: frozenset[str] = frozenset(
    {
        "CreateBucket",
        "DeleteBucket",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "PutBucketVersioning",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
        "PutBucketLifecycleConfiguration",
        "PutBucketLogging",
        "PutBucketEncryption",
        "PutBucketReplication",
    }
)

_SECRETS_READ_APIS: frozenset[str] = frozenset(
    {"GetSecretValue", "BatchGetSecretValue", "DescribeSecret", "ListSecrets", "ListSecretVersionIds"}
)
_SECRETS_WRITE_APIS: frozenset[str] = frozenset(
    {"CreateSecret", "PutSecretValue", "UpdateSecret", "DeleteSecret", "RestoreSecret", "RotateSecret"}
)

_KMS_CRYPTO_APIS: frozenset[str] = frozenset(
    {"Decrypt", "Encrypt", "ReEncrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateRandom", "Sign", "Verify"}
)
_KMS_MANAGEMENT_APIS: frozenset[str] = frozenset(
    {"CreateKey", "ScheduleKeyDeletion", "CancelKeyDeletion", "DisableKey", "EnableKey", "CreateGrant", "RevokeGrant", "PutKeyPolicy", "CreateAlias", "DeleteAlias", "UpdateAlias"}
)

_LAMBDA_WRITE_APIS: frozenset[str] = frozenset(
    {"CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration", "DeleteFunction", "AddPermission", "CreateEventSourceMapping", "UpdateFunctionUrlConfig", "PublishVersion"}
)

#: Verb prefixes used as a last-resort read/write heuristic.
_WRITE_PREFIXES: tuple[str, ...] = (
    "Create", "Put", "Update", "Delete", "Attach", "Detach", "Modify", "Set",
    "Add", "Remove", "Authorize", "Revoke", "Enable", "Disable", "Register",
    "Deregister", "Associate", "Disassociate", "Import", "Restore", "Cancel",
    "Tag", "Untag", "Start", "Stop", "Terminate", "Reboot", "Run", "Reset",
    "Replace", "Assign", "Unassign", "Publish", "Upload", "Schedule", "Move",
    "Copy", "Rotate", "Accept", "Reject", "Invite", "Leave", "Promote",
)

_READ_PREFIXES: tuple[str, ...] = (
    "Get", "List", "Describe", "Head", "Lookup", "Search", "Query", "View",
    "Check", "Validate", "Test", "Preview", "BatchGet", "BatchDescribe",
    "Scan", "Select", "Download", "Export", "Read", "Resolve",
)

#: Crypto/session APIs whose verb prefix does not convey a direction.
_ACCESS_OVERRIDES: dict[str, AccessType] = {
    "Decrypt": AccessType.READ,
    "ReEncrypt": AccessType.READ,
    "Verify": AccessType.READ,
    "GenerateDataKey": AccessType.READ,
    "GenerateDataKeyWithoutPlaintext": AccessType.READ,
    "GenerateRandom": AccessType.READ,
    "Encrypt": AccessType.WRITE,
    "Sign": AccessType.WRITE,
    "GetSessionToken": AccessType.WRITE,
    "GetFederationToken": AccessType.WRITE,
}


class ApiClassification(BaseModel):
    """Result of classifying one AWS API call."""

    model_config = ConfigDict(frozen=True)

    service_name: str
    api_family: str
    read_or_write: AccessType
    event_category: EventCategory
    privilege_change: bool


class AwsApiClassifier:
    """Maps ``eventSource`` + ``eventName`` to family, direction and category."""

    @staticmethod
    def service_name(event_source: str) -> str:
        """``iam.amazonaws.com`` -> ``iam``."""
        source = (event_source or "").strip().lower()
        for suffix in (".amazonaws.com.cn", ".amazonaws.com", ".amazonaws.cn"):
            if source.endswith(suffix):
                source = source[: -len(suffix)]
                break
        return source or "unknown"

    def classify(self, event_source: str, event_name: str) -> ApiClassification:
        service = self.service_name(event_source)
        name = (event_name or "").strip()

        # Console sign-in / SSO.
        if service in {"signin", "sso", "sts"} and name in {"ConsoleLogin", "Login"}:
            return ApiClassification(
                service_name="signin",
                api_family=ApiFamilies.CONSOLE_SIGNIN,
                read_or_write=AccessType.READ,
                event_category=EventCategory.SIGNIN,
                privilege_change=False,
            )

        access = self.classify_access(name)

        family = self._family_for(service, name, access)
        category = self._category_for(service, family)

        return ApiClassification(
            service_name=service,
            api_family=family,
            read_or_write=access,
            event_category=category,
            privilege_change=family in PRIVILEGE_MUTATION_FAMILIES,
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def classify_access(event_name: str) -> AccessType:
        name = event_name or ""
        override = _ACCESS_OVERRIDES.get(name)
        if override is not None:
            return override
        for prefix in _READ_PREFIXES:
            if name.startswith(prefix):
                return AccessType.READ
        for prefix in _WRITE_PREFIXES:
            if name.startswith(prefix):
                return AccessType.WRITE
        return AccessType.UNKNOWN

    def _family_for(self, service: str, name: str, access: AccessType) -> str:
        if name in _PRIVILEGE_MUTATION_APIS:
            return ApiFamilies.IAM_PRIVILEGE_MUTATION
        if name in _CREDENTIAL_MANAGEMENT_APIS:
            return ApiFamilies.CREDENTIAL_MANAGEMENT
        if name in _SECURITY_CONTROL_TAMPER:
            return _SECURITY_CONTROL_TAMPER[name]
        if name in _STS_APIS:
            return ApiFamilies.STS_SESSION

        if service == "s3":
            if name in _S3_READ_APIS:
                return ApiFamilies.S3_DATA_READ
            if name in _S3_WRITE_APIS:
                return ApiFamilies.S3_DATA_WRITE
            if name in _S3_MANAGEMENT_APIS:
                return ApiFamilies.S3_MANAGEMENT
            return (
                ApiFamilies.S3_DATA_READ
                if access is AccessType.READ
                else ApiFamilies.S3_DATA_WRITE
            )

        if service == "secretsmanager":
            if name in _SECRETS_READ_APIS:
                return ApiFamilies.SECRETS_ACCESS
            if name in _SECRETS_WRITE_APIS:
                return ApiFamilies.SECRETS_MANAGEMENT
            return (
                ApiFamilies.SECRETS_ACCESS
                if access is AccessType.READ
                else ApiFamilies.SECRETS_MANAGEMENT
            )

        if service == "kms":
            if name in _KMS_CRYPTO_APIS:
                return ApiFamilies.KMS_CRYPTO
            if name in _KMS_MANAGEMENT_APIS:
                return ApiFamilies.KMS_MANAGEMENT
            return (
                ApiFamilies.KMS_CRYPTO
                if access is AccessType.READ
                else ApiFamilies.KMS_MANAGEMENT
            )

        if service == "lambda":
            # Both ``Invoke*`` (read-like) and function mutation share one family;
            # the read/write direction is carried separately on the event.
            return ApiFamilies.LAMBDA_MANAGEMENT

        if service == "sts":
            return ApiFamilies.STS_SESSION
        if service == "iam":
            return (
                ApiFamilies.IAM_READ
                if access is AccessType.READ
                else ApiFamilies.IAM_USER_MANAGEMENT
            )
        if service == "ec2":
            return ApiFamilies.EC2_READ if access is AccessType.READ else ApiFamilies.EC2_MANAGEMENT
        if service == "organizations":
            return ApiFamilies.ORGANIZATIONS_MANAGEMENT
        if service == "eks":
            return ApiFamilies.EKS_MANAGEMENT
        if service == "rds":
            return ApiFamilies.RDS_MANAGEMENT
        if service == "logs":
            # Deleting log groups/streams is control-plane tampering with the
            # same investigative impact as tampering with CloudTrail itself.
            return (
                ApiFamilies.CLOUDTRAIL_TAMPER
                if name in {"DeleteLogGroup", "DeleteLogStream", "PutRetentionPolicy"}
                else ApiFamilies.DEFAULT
            )

        return f"{service.upper()}_API" if service else ApiFamilies.DEFAULT

    @staticmethod
    def _category_for(service: str, family: str) -> EventCategory:
        if family == ApiFamilies.CONSOLE_SIGNIN:
            return EventCategory.SIGNIN
        if family in {ApiFamilies.S3_DATA_READ, ApiFamilies.S3_DATA_WRITE, ApiFamilies.SECRETS_ACCESS}:
            return EventCategory.DATA
        return EventCategory.MANAGEMENT


# --------------------------------------------------------------------------- #
# Batch result
# --------------------------------------------------------------------------- #


class QuarantinedRecord(BaseModel):
    """A record that failed normalization, kept for auditing - never dropped."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    raw_reference: Optional[str] = None
    error_type: str
    message: str
    context: dict[str, Any] = Field(default_factory=dict)
    raw_payload: Optional[dict[str, Any]] = None


class NormalizationResult(BaseModel):
    """Outcome of normalizing a batch of raw CloudTrail records."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    events: list[IdentityActivityEvent] = Field(default_factory=list)
    quarantined: list[QuarantinedRecord] = Field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return len(self.events)

    @property
    def error_count(self) -> int:
        return len(self.quarantined)

    @property
    def has_errors(self) -> bool:
        return bool(self.quarantined)


# --------------------------------------------------------------------------- #
# Normalizer
# --------------------------------------------------------------------------- #


class CloudTrailNormalizer:
    """Transforms raw CloudTrail payloads into canonical identity events."""

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        *,
        enricher: Optional[IpEnricher] = None,
        resolver: Optional[IdentityResolver] = None,
        classifier: Optional[AwsApiClassifier] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.ingest: IngestConfig = self.config.ingest
        self.enricher: IpEnricher = enricher or NullIpEnricher()
        self.resolver = resolver or IdentityResolver(provider=CloudProvider.AWS)
        self.classifier = classifier or AwsApiClassifier()

    # ------------------------------------------------------------------ #
    # Payload shaping
    # ------------------------------------------------------------------ #

    @staticmethod
    def extract_records(payload: Any) -> list[dict[str, Any]]:
        """Accept raw record, EventBridge envelope or S3 delivery file."""
        if isinstance(payload, Mapping):
            records = payload.get("Records")
            if isinstance(records, Sequence) and not isinstance(records, (str, bytes)):
                return [dict(r) for r in records if isinstance(r, Mapping)]
            detail = payload.get("detail")
            if isinstance(detail, Mapping) and "eventName" in detail:
                return [dict(detail)]
            if "eventName" in payload:
                return [dict(payload)]
            raise MalformedEventError(
                "payload is not a recognised CloudTrail shape",
                context={"keys": sorted(str(k) for k in payload.keys())},
            )
        if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
            return [dict(r) for r in payload if isinstance(r, Mapping)]
        raise MalformedEventError(
            "payload must be an object or a list of records",
            context={"got": type(payload).__name__},
        )

    # ------------------------------------------------------------------ #
    # Normalization
    # ------------------------------------------------------------------ #

    def normalize(
        self,
        record: Mapping[str, Any],
        *,
        raw_event_reference: Optional[str] = None,
    ) -> IdentityActivityEvent:
        """Normalize one CloudTrail record, or raise :class:`MalformedEventError`."""
        if not isinstance(record, Mapping):
            raise MalformedEventError("record must be an object", context={"got": type(record).__name__})

        missing = [field for field in REQUIRED_RECORD_FIELDS if not record.get(field)]
        if missing:
            raise MalformedEventError(
                "CloudTrail record is missing required fields",
                missing_fields=missing,
                context={"eventID": record.get("eventID")},
            )

        warnings: list[str] = []

        event_time = self._parse_timestamp(record.get("eventTime"), field="eventTime")

        user_identity = record.get("userIdentity")
        if not isinstance(user_identity, Mapping):
            raise MalformedEventError(
                "record has no usable userIdentity block",
                context={"eventID": record.get("eventID")},
            )

        account_id = (
            user_identity.get("accountId")
            or record.get("recipientAccountId")
        )
        identity = self.resolver.resolve(
            user_identity,
            account_id=account_id,
            invoked_by=record.get("invokedBy"),
        )

        classification = self.classifier.classify(
            str(record.get("eventSource", "")), str(record.get("eventName", ""))
        )

        # Source IP: tolerate AWS pseudo-sources, but record the fact.
        raw_ip = record.get("sourceIPAddress")
        source_ip: Optional[str] = None
        if raw_ip:
            try:
                source_ip = normalize_ip(str(raw_ip))
            except ValueError:
                warnings.append(f"unparseable_source_ip:{raw_ip}")

        intelligence = self.enricher.enrich(source_ip)

        mfa = self._mfa_state(user_identity, record.get("additionalEventData"))
        session_creation = self._session_creation_time(user_identity)

        reference = raw_event_reference or self._default_reference(record, account_id)

        return IdentityActivityEvent(
            event_id=str(record["eventID"]),
            timestamp=event_time,
            provider=CloudProvider.AWS,
            account_id=account_id,
            region=record.get("awsRegion"),
            region_hint=intelligence.region_hint,
            principal_id=identity.principal_id,
            principal_name=identity.principal_name,
            principal_type=identity.principal_type,
            identity_kind=identity.identity_kind,
            baseline_category=identity.baseline_category,
            identity_key=identity.identity_key,
            access_key_id=user_identity.get("accessKeyId") or None,
            role_arn=identity.role_arn,
            session_id=identity.session_id,
            session_creation_time=session_creation,
            is_human_session=identity.is_human_session,
            event_source=str(record["eventSource"]),
            event_name=str(record["eventName"]),
            event_category=classification.event_category,
            service_name=classification.service_name,
            api_family=classification.api_family,
            read_or_write=classification.read_or_write,
            privilege_change=classification.privilege_change,
            source_ip=source_ip,
            country=intelligence.country,
            asn=intelligence.asn,
            user_agent=record.get("userAgent"),
            mfa_authenticated=mfa,
            request_rate_context=None,
            raw_event_reference=reference,
            normalization_warnings=tuple(warnings[: self.ingest.max_parse_warnings]),
        )

    def normalize_batch(
        self,
        payload: Any,
        *,
        raw_event_reference: Optional[str] = None,
        strict: Optional[bool] = None,
    ) -> NormalizationResult:
        """Normalize a batch, quarantining bad records unless ``strict``."""
        strict = self.ingest.strict if strict is None else strict
        records = self.extract_records(payload)
        if len(records) > self.ingest.max_records_per_batch:
            raise MalformedEventError(
                "batch exceeds max_records_per_batch",
                context={"size": len(records), "limit": self.ingest.max_records_per_batch},
            )

        result = NormalizationResult()
        for index, record in enumerate(records):
            try:
                result.events.append(self.normalize(record, raw_event_reference=raw_event_reference))
            except MalformedEventError as exc:
                if strict:
                    raise
                if not self.ingest.quarantine_on_error:
                    raise
                result.quarantined.append(
                    QuarantinedRecord(
                        raw_reference=record.get("eventID") or f"index:{index}",
                        error_type=type(exc).__name__,
                        message=exc.message,
                        context=exc.context,
                        raw_payload=dict(record),
                    )
                )
        return result

    def normalize_iter(
        self, records: Iterable[Mapping[str, Any]]
    ) -> Iterable[IdentityActivityEvent]:
        """Lazily normalize records, raising on the first bad record."""
        for record in records:
            yield self.normalize(record)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_timestamp(value: Any, *, field: str) -> Any:
        if value is None:
            raise MalformedEventError(f"missing {field}", missing_fields=[field])
        try:
            return ensure_utc(
                value if hasattr(value, "tzinfo") else _parse_isoformat(str(value))
            )
        except (TypeError, ValueError) as exc:
            raise MalformedEventError(
                f"{field} is not a valid ISO-8601 timestamp",
                context={"value": value},
            ) from exc

    @staticmethod
    def _mfa_state(
        user_identity: Mapping[str, Any], additional_event_data: Any
    ) -> Optional[bool]:
        attributes = (user_identity.get("sessionContext") or {}).get("attributes") or {}
        raw = attributes.get("mfaAuthenticated")
        if raw is None and isinstance(additional_event_data, Mapping):
            raw = additional_event_data.get("MFAUsed")
        if raw is None:
            return None
        return str(raw).strip().lower() in {"true", "yes"}

    @staticmethod
    def _session_creation_time(user_identity: Mapping[str, Any]) -> Optional[Any]:
        attributes = (user_identity.get("sessionContext") or {}).get("attributes") or {}
        raw = attributes.get("creationDate")
        if not raw:
            return None
        try:
            return ensure_utc(_parse_isoformat(str(raw)))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _default_reference(record: Mapping[str, Any], account_id: Optional[str]) -> str:
        return f"cloudtrail:{account_id or 'unknown'}:{record.get('eventID')}"


def _parse_isoformat(value: str) -> Any:
    from datetime import datetime

    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate)


__all__ = [
    "ApiClassification",
    "AwsApiClassifier",
    "CloudTrailNormalizer",
    "IpEnricher",
    "NormalizationResult",
    "NullIpEnricher",
    "QuarantinedRecord",
    "REQUIRED_RECORD_FIELDS",
]
