"""Identity resolution tests."""

from __future__ import annotations

import pytest

from detection.credential_compromise.exceptions import IdentityResolutionError
from detection.credential_compromise.identity import IdentityResolver
from detection.credential_compromise.schemas import (
    BaselineCategory,
    IdentityKind,
    PrincipalType,
)


@pytest.fixture
def resolver() -> IdentityResolver:
    return IdentityResolver()


def test_iam_user_resolution(cloudtrail, resolver):
    record = cloudtrail("console_login_mfa.json")
    identity = resolver.resolve(record["userIdentity"])

    assert identity.principal_type is PrincipalType.IAM_USER
    assert identity.identity_kind is IdentityKind.HUMAN
    assert identity.baseline_category is BaselineCategory.HUMAN_USER
    assert identity.principal_name == "aniruddha"
    assert identity.principal_id == "arn:aws:iam::123456789012:user/aniruddha"
    assert identity.account_id == "123456789012"
    assert identity.is_human_session is True
    assert identity.role_arn is None


def test_assumed_role_baselines_on_the_role(cloudtrail, resolver):
    record = cloudtrail("s3_get_object.json")
    identity = resolver.resolve(record["userIdentity"])

    assert identity.principal_type is PrincipalType.ASSUMED_ROLE
    assert identity.baseline_category is BaselineCategory.ASSUMED_ROLE
    assert identity.identity_kind is IdentityKind.HUMAN
    # Baseline accumulates on the role, not the ephemeral session.
    assert identity.principal_id == "arn:aws:iam::123456789012:role/DataAnalyst"
    # The session itself stays distinguishable.
    assert identity.session_id == "arn:aws:sts::123456789012:assumed-role/DataAnalyst/alice"
    assert identity.principal_name == "alice"


def test_web_identity_assumption_is_federated(cloudtrail, resolver):
    record = cloudtrail("assume_role_web_identity.json")
    identity = resolver.resolve(record["userIdentity"])

    assert identity.baseline_category is BaselineCategory.FEDERATED_IDENTITY
    assert identity.identity_kind is IdentityKind.FEDERATED
    assert identity.principal_type is PrincipalType.FEDERATED_USER
    assert identity.principal_id == "arn:aws:iam::123456789012:role/CorpAdmin"
    assert identity.session_id == (
        "arn:aws:sts::123456789012:assumed-role/CorpAdmin/aniruddha@corp.example.com"
    )


def test_aws_service_is_its_own_category(cloudtrail, resolver):
    record = cloudtrail("aws_service_event.json")
    identity = resolver.resolve(record["userIdentity"], account_id="123456789012")

    assert identity.principal_type is PrincipalType.AWS_SERVICE
    assert identity.identity_kind is IdentityKind.SERVICE
    assert identity.baseline_category is BaselineCategory.SERVICE_IDENTITY
    assert identity.principal_id == "aws-service:autoscaling.amazonaws.com"
    assert identity.is_human_session is False


def test_humans_and_machines_get_different_baseline_buckets(cloudtrail, resolver):
    human = resolver.resolve(cloudtrail("console_login_mfa.json")["userIdentity"])
    machine = resolver.resolve(
        cloudtrail("aws_service_event.json")["userIdentity"], account_id="123456789012"
    )

    assert human.baseline_category != machine.baseline_category
    assert human.identity_key != machine.identity_key
    assert ":human_user:" in human.identity_key
    assert ":service_identity:" in machine.identity_key


def test_root_identity(resolver):
    identity = resolver.resolve(
        {"type": "Root", "arn": "arn:aws:iam::123456789012:root", "accountId": "123456789012"}
    )
    assert identity.principal_type is PrincipalType.ROOT
    assert identity.baseline_category is BaselineCategory.HUMAN_USER
    assert identity.is_human_session is True


def test_service_account_is_machine(resolver):
    identity = resolver.resolve(
        {
            "type": "ServiceAccount",
            "arn": "arn:aws:iam::123456789012:user/github-actions-deployer",
            "userName": "github-actions-deployer",
        }
    )
    assert identity.identity_kind is IdentityKind.MACHINE
    assert identity.baseline_category is BaselineCategory.MACHINE_IDENTITY


def test_unknown_principal_type_is_conservatively_machine(resolver):
    identity = resolver.resolve(
        {"type": "SomethingNew", "principalId": "PRINCIPAL:123"}, account_id="123456789012"
    )
    assert identity.principal_type is PrincipalType.UNKNOWN
    assert identity.identity_kind is IdentityKind.UNKNOWN
    assert identity.baseline_category is BaselineCategory.UNKNOWN


def test_service_role_session_is_treated_as_service(resolver):
    identity = resolver.resolve(
        {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForAutoScaling/asg-1",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                }
            },
        }
    )
    assert identity.baseline_category is BaselineCategory.SERVICE_IDENTITY
    assert identity.identity_kind is IdentityKind.SERVICE
    assert identity.is_human_session is False


def test_unresolvable_identity_raises(resolver):
    with pytest.raises(IdentityResolutionError):
        resolver.resolve({"type": "IAMUser"})


def test_non_object_user_identity_raises(resolver):
    with pytest.raises(IdentityResolutionError):
        resolver.resolve(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_identity_key_is_deterministic(resolver):
    ui = {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/aniruddha",
        "accountId": "123456789012",
        "userName": "aniruddha",
    }
    assert resolver.resolve(ui).identity_key == resolver.resolve(ui).identity_key
