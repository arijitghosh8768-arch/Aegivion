import sys
import os

# Ensure sibling packages (security, ai) are in sys.path
models_dir = os.path.dirname(os.path.abspath(__file__))  # app/models
app_dir = os.path.dirname(models_dir)  # app
backend_dir = os.path.dirname(app_dir)  # packages/backend
packages_dir = os.path.dirname(backend_dir)  # packages

if packages_dir not in sys.path:
    sys.path.append(packages_dir)

# Import Base
from app.database import Base

# Import backend domain models
from app.models.organization import Organization, SubscriptionPlan
from app.models.role import Role
from app.models.user import User, UserStatus
from app.models.audit_log import AuditLog, AuditAction
from app.models.cloud_account import CloudAccountV2
from app.models.cloud import CloudAsset, SecurityGroupAsset, IAMUserAsset, S3BucketAsset, EC2InstanceAsset, CloudAccountStatus, CloudProvider, ScanJob, ScanStatus, Relationship

# Import security domain models
from security.models.finding import Finding, FindingStatus, FindingSeverity, FindingSource

# Import AI domain models
from ai.models.knowledge import KnowledgeBase, Conversation, KnowledgeCategory

# Import Compliance models
from app.models.compliance import ComplianceControlResult, ComplianceStatus

# Import Reports models
from app.models.reports import SecurityPostureSnapshot, GeneratedReport, ReportType, ReportStatus

# Import History and Dataset models
from app.models.history import AssetSnapshot, SecurityRiskSnapshot, FindingSuppression

