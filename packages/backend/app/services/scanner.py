from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid
from app.models.cloud import CloudAccount, CloudAsset, SecurityGroupAsset, IAMUserAsset, S3BucketAsset, EC2InstanceAsset, CloudProvider, CloudAccountStatus
from app.models.organization import Organization
from security.models.finding import Finding, FindingStatus, FindingSeverity, FindingSource
from app.aws.client import get_aws_session
from app.aws.s3 import discover_s3_buckets
from app.aws.ec2 import discover_ec2_instances
from app.aws.iam import discover_iam_users
from app.aws.rds import discover_rds_instances
from app.aws.security_groups import discover_security_groups

def serialize_datetime(obj):
    if isinstance(obj, dict):
        return {k: serialize_datetime(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_datetime(i) for i in obj]
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj

def discover_vpcs(session=None) -> list:
    if session is None:
        return [{"vpc_id": "vpc-011223344", "cidr_block": "10.0.0.0/16", "is_default": False, "region": "ap-south-1"}]
    client = session.client("ec2")
    discovered = []
    try:
        resp = client.describe_vpcs()
        for vpc in resp.get("Vpcs", []):
            discovered.append({
                "vpc_id": vpc["VpcId"],
                "cidr_block": vpc["CidrBlock"],
                "is_default": vpc.get("IsDefault", False),
                "region": session.region_name
            })
    except Exception as e:
        print(f"Error listing VPCs: {e}")
    return discovered

def discover_cloudtrail_trails(session=None) -> list:
    if session is None:
        return [{"trail_name": "aegivion-audit-trail", "is_logging": True, "multi_region": True, "region": "ap-south-1"}]
    client = session.client("cloudtrail")
    discovered = []
    try:
        resp = client.describe_trails()
        for trail in resp.get("trailList", []):
            name = trail["Name"]
            arn = trail.get("TrailARN")
            multi_region = trail.get("IsMultiRegionTrail", False)
            
            is_logging = False
            try:
                status = client.get_trail_status(Name=name)
                is_logging = status.get("IsLogging", False)
            except Exception:
                pass
                
            discovered.append({
                "trail_name": name,
                "arn": arn,
                "is_logging": is_logging,
                "multi_region": multi_region,
                "region": session.region_name
            })
    except Exception as e:
        print(f"Error listing CloudTrail trails: {e}")
    return discovered

def run_cloud_scan(db: Session, account_id: str = None) -> dict:
    if account_id:
        account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
    else:
        account = db.query(CloudAccount).first()
        
    if not account:
        org = db.query(Organization).first()
        if not org:
            org = Organization(name="Default Org", slug="default-org")
            db.add(org)
            db.commit()
            db.refresh(org)
        
        account = CloudAccount(
            name="Primary AWS Account",
            provider=CloudProvider.AWS,
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_region="ap-south-1",
            organization_id=org.id,
            status=CloudAccountStatus.CONNECTED
        )
        db.add(account)
        db.commit()
        db.refresh(account)

    session = get_aws_session(
        aws_access_key_id=account.aws_access_key_id,
        aws_secret_access_key=account.aws_secret_access_key,
        aws_region=account.aws_region
    )
    
    account.last_scan_at = datetime.utcnow()
    db.commit()

    s3_buckets = discover_s3_buckets(session)
    ec2_instances = discover_ec2_instances(session)
    iam_users = discover_iam_users(session)
    rds_instances = discover_rds_instances(session)
    security_groups = discover_security_groups(session)
    vpcs = discover_vpcs(session)
    trails = discover_cloudtrail_trails(session)

    db.query(CloudAsset).filter(CloudAsset.account_id == account.id).delete()
    db.commit()

    db.query(Finding).filter(Finding.cloud_provider == "AWS").delete()
    db.commit()

    findings_to_create = []

    for bucket in s3_buckets:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=bucket["arn"],
            name=bucket["bucket_name"],
            type="aws_s3_bucket",
            region=bucket["region"],
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(bucket)
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        s3_detail = S3BucketAsset(
            asset_id=asset.id,
            bucket_name=bucket["bucket_name"],
            arn=bucket["arn"],
            is_public=bucket["is_public"],
            encryption_enabled=bucket["encryption_enabled"],
            versioning_enabled=bucket["versioning_enabled"]
        )
        db.add(s3_detail)
        db.commit()

        if bucket["is_public"]:
            findings_to_create.append(Finding(
                title=f"S3 Bucket {bucket['bucket_name']} Publicly Accessible",
                description=f"The S3 bucket '{bucket['bucket_name']}' allows public read or write access. Anyone on the internet can read or write to it.",
                severity=FindingSeverity.HIGH,
                status=FindingStatus.OPEN,
                source=FindingSource.CSPM,
                resource_id=bucket["arn"],
                resource_name=bucket["bucket_name"],
                resource_type="aws_s3_bucket",
                resource_region=bucket["region"],
                cloud_provider="AWS",
                rule_id="rule-s3-public",
                rule_name="Block S3 Public Access",
                risk_score=7.5,
                remediation_steps=["Enable 'Block all public access' settings in AWS Console", "Apply explicit deny bucket policies"],
                evidence={"is_public": True, "bucket_name": bucket["bucket_name"]}
            ))

    for inst in ec2_instances:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=inst["instance_id"],
            name=inst["instance_id"],
            type="aws_ec2_instance",
            region=inst["region"],
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(inst)
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        ec2_detail = EC2InstanceAsset(
            asset_id=asset.id,
            instance_id=inst["instance_id"],
            state=inst["state"],
            public_ip=inst["public_ip"],
            private_ip=inst["private_ip"],
            instance_type=inst["instance_type"],
            security_groups=inst["security_groups"],
            has_public_ip=inst["has_public_ip"]
        )
        db.add(ec2_detail)
        db.commit()

        has_port_22_open = False
        associated_sg_ids = [sg["GroupId"] for sg in inst["security_groups"]]
        for sg in security_groups:
            if sg["group_id"] in associated_sg_ids:
                for rule in sg["ingress_rules"]:
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_ranges = rule.get("IpRanges", [])
                    
                    is_ssh = (from_port == 22 or to_port == 22 or (from_port is not None and from_port <= 22 and to_port is not None and to_port >= 22))
                    is_open_to_all = any(ip.get("CidrIp") == "0.0.0.0/0" for ip in ip_ranges)
                    
                    if is_ssh and is_open_to_all:
                        has_port_22_open = True
                        break
        
        if inst["has_public_ip"] and has_port_22_open:
            findings_to_create.append(Finding(
                title=f"EC2 Instance {inst['instance_id']} Exposes SSH to Public Internet",
                description=f"EC2 Instance '{inst['instance_id']}' has a public IP and associated Security Groups allow inbound TCP port 22 (SSH) traffic from anywhere (0.0.0.0/0).",
                severity=FindingSeverity.CRITICAL,
                status=FindingStatus.OPEN,
                source=FindingSource.NETWORK,
                resource_id=inst["instance_id"],
                resource_name=inst["instance_id"],
                resource_type="aws_ec2_instance",
                resource_region=inst["region"],
                cloud_provider="AWS",
                rule_id="rule-ssh-open",
                rule_name="SSH Security Ingress Limits",
                risk_score=10.0,
                remediation_steps=["Restrict SSH access to trusted IPs in Security Groups", "Disable public IP if not needed"],
                evidence={"public_ip": inst["public_ip"], "port_22_open": True}
            ))

    for user in iam_users:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=user["arn"],
            name=user["username"],
            type="aws_iam_user",
            region="global",
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(user)
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        iam_detail = IAMUserAsset(
            asset_id=asset.id,
            username=user["username"],
            arn=user["arn"],
            mfa_enabled=user["mfa_enabled"],
            is_admin=user["is_admin"],
            access_keys_age_days=user["access_keys_age_days"],
            last_active=user["last_active"]
        )
        db.add(iam_detail)
        db.commit()

        if user["is_admin"] and not user["mfa_enabled"]:
            findings_to_create.append(Finding(
                title=f"IAM Admin User {user['username']} MFA Disabled",
                description=f"IAM User '{user['username']}' has administrative privileges but MFA is not enabled. If credentials leak, attackers gain full access.",
                severity=FindingSeverity.CRITICAL,
                status=FindingStatus.OPEN,
                source=FindingSource.IAM,
                resource_id=user["arn"],
                resource_name=user["username"],
                resource_type="aws_iam_user",
                resource_region="global",
                cloud_provider="AWS",
                rule_id="rule-iam-admin-mfa",
                rule_name="Admin MFA Required",
                risk_score=9.5,
                remediation_steps=["Enable MFA for the user in the AWS IAM Console"],
                evidence={"is_admin": True, "mfa_enabled": False}
            ))
            
        if user["access_keys_age_days"] and user["access_keys_age_days"] > 90:
            findings_to_create.append(Finding(
                title=f"IAM User {user['username']} Access Keys Older Than 90 Days",
                description=f"IAM User '{user['username']}' has access keys that are older than 90 days (Age: {user['access_keys_age_days']} days). Regular rotation is required.",
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.OPEN,
                source=FindingSource.IAM,
                resource_id=user["arn"],
                resource_name=user["username"],
                resource_type="aws_iam_user",
                resource_region="global",
                cloud_provider="AWS",
                rule_id="rule-iam-key-rotation",
                rule_name="Access Key Rotation Required",
                risk_score=5.0,
                remediation_steps=["Create new access keys, update applications, and delete old keys in AWS IAM Console"],
                evidence={"access_key_age_days": user["access_keys_age_days"]}
            ))

    for db_inst in rds_instances:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=db_inst["arn"],
            name=db_inst["db_instance_identifier"],
            type="aws_rds_instance",
            region=db_inst["region"],
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(db_inst)
        )
        db.add(asset)
        db.commit()

        if db_inst["publicly_accessible"]:
            findings_to_create.append(Finding(
                title=f"RDS Instance {db_inst['db_instance_identifier']} Publicly Accessible",
                description=f"RDS database instance '{db_inst['db_instance_identifier']}' has public accessibility enabled, exposing the database port to the internet.",
                severity=FindingSeverity.HIGH,
                status=FindingStatus.OPEN,
                source=FindingSource.DATA,
                resource_id=db_inst["arn"],
                resource_name=db_inst["db_instance_identifier"],
                resource_type="aws_rds_instance",
                resource_region=db_inst["region"],
                cloud_provider="AWS",
                rule_id="rule-rds-public",
                rule_name="RDS Private Endpoint Required",
                risk_score=8.0,
                remediation_steps=["Set 'Publicly accessible' option to 'No' in RDS configuration"],
                evidence={"publicly_accessible": True}
            ))

        if not db_inst["storage_encrypted"]:
            findings_to_create.append(Finding(
                title=f"RDS Instance {db_inst['db_instance_identifier']} Encryption Disabled",
                description=f"RDS database instance '{db_inst['db_instance_identifier']}' storage is not encrypted at rest. Data could be exposed if disk storage is leaked.",
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.OPEN,
                source=FindingSource.DATA,
                resource_id=db_inst["arn"],
                resource_name=db_inst["db_instance_identifier"],
                resource_type="aws_rds_instance",
                resource_region=db_inst["region"],
                cloud_provider="AWS",
                rule_id="rule-rds-encryption",
                rule_name="RDS Storage Encryption Required",
                risk_score=5.0,
                remediation_steps=["Recreate RDS instance with storage encryption enabled or enable encryption on a snapshot restore"],
                evidence={"storage_encrypted": False}
            ))

    for sg in security_groups:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=sg["group_id"],
            name=sg["group_name"],
            type="aws_security_group",
            region=sg["region"],
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(sg)
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        sg_detail = SecurityGroupAsset(
            asset_id=asset.id,
            group_id=sg["group_id"],
            group_name=sg["group_name"],
            vpc_id=sg["vpc_id"],
            ingress_rules=sg["ingress_rules"],
            egress_rules=sg["egress_rules"]
        )
        db.add(sg_detail)
        db.commit()

    for vpc in vpcs:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=vpc["vpc_id"],
            name=vpc["vpc_id"],
            type="aws_vpc",
            region=vpc["region"],
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(vpc)
        )
        db.add(asset)
        db.commit()

    for trail in trails:
        asset = CloudAsset(
            account_id=account.id,
            resource_id=trail.get("arn") or f"arn:aws:cloudtrail:global:trail/{trail['trail_name']}",
            name=trail["trail_name"],
            type="aws_cloudtrail",
            region=trail["region"],
            provider=CloudProvider.AWS,
            metadata_json=serialize_datetime(trail)
        )
        db.add(asset)
        db.commit()
        
        if not trail["is_logging"]:
            findings_to_create.append(Finding(
                title=f"CloudTrail {trail['trail_name']} Logging Disabled",
                description=f"CloudTrail trail '{trail['trail_name']}' is not currently logging events. Auditing and breach detection will be ineffective.",
                severity=FindingSeverity.HIGH,
                status=FindingStatus.OPEN,
                source=FindingSource.CSPM,
                resource_id=trail.get("arn") or f"arn:aws:cloudtrail:global:trail/{trail['trail_name']}",
                resource_name=trail["trail_name"],
                resource_type="aws_cloudtrail",
                resource_region=trail["region"],
                cloud_provider="AWS",
                rule_id="rule-cloudtrail-logging",
                rule_name="CloudTrail Auditing Required",
                risk_score=7.0,
                remediation_steps=["Start logging on the trail in CloudTrail Console"],
                evidence={"is_logging": False}
            ))

    for finding in findings_to_create:
        db.add(finding)
    db.commit()

    from app.core.websocket import ws_manager
    import asyncio
    for f in findings_to_create:
        f_data = {
            "finding_id": str(f.id),
            "title": f.title,
            "severity": f.severity.value.capitalize(),
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "cloud_provider": f.cloud_provider,
            "description": f.description,
            "remediation": f.remediation_steps[0] if f.remediation_steps else "Fix it."
        }
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(ws_manager.broadcast({"type": "new_finding", "data": f_data}))
        except Exception:
            pass

    return {
        "success": True,
        "scanned_assets_count": len(s3_buckets) + len(ec2_instances) + len(iam_users) + len(rds_instances) + len(security_groups) + len(vpcs) + len(trails),
        "findings_count": len(findings_to_create)
    }
