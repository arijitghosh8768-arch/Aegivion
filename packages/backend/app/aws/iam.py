import boto3
from datetime import datetime, timezone

def discover_iam_users(session=None) -> list:
    if session is None:
        return [
            {
                "username": "aegivion-scanner",
                "arn": "arn:aws:iam::123456789012:user/aegivion-scanner",
                "mfa_enabled": False,
                "is_admin": True,
                "access_keys_age_days": 105,
                "last_active": datetime.now(timezone.utc)
            },
            {
                "username": "read-only-user",
                "arn": "arn:aws:iam::123456789012:user/read-only-user",
                "mfa_enabled": True,
                "is_admin": False,
                "access_keys_age_days": 15,
                "last_active": None
            }
        ]

    iam = session.client("iam")
    discovered = []
    try:
        users_resp = iam.list_users()
        for user in users_resp.get("Users", []):
            username = user["UserName"]
            arn = user["Arn"]
            
            mfa_enabled = False
            try:
                mfa_resp = iam.list_mfa_devices(UserName=username)
                if len(mfa_resp.get("MFADevices", [])) > 0:
                    mfa_enabled = True
            except Exception:
                pass
                
            access_keys_age_days = None
            try:
                keys_resp = iam.list_access_keys(UserName=username)
                for key in keys_resp.get("AccessKeyMetadata", []):
                    create_date = key["CreateDate"]
                    age = (datetime.now(timezone.utc) - create_date).days
                    if access_keys_age_days is None or age > access_keys_age_days:
                        access_keys_age_days = age
            except Exception:
                pass
            
            is_admin = False
            try:
                user_policies = iam.list_attached_user_policies(UserName=username)
                for policy in user_policies.get("AttachedPolicies", []):
                    if policy["PolicyName"] == "AdministratorAccess" or "Admin" in policy["PolicyName"]:
                        is_admin = True
                
                groups_resp = iam.list_groups_for_user(UserName=username)
                for group in groups_resp.get("Groups", []):
                    group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])
                    for p in group_policies.get("AttachedPolicies", []):
                        if p["PolicyName"] == "AdministratorAccess" or "Admin" in p["PolicyName"]:
                            is_admin = True
            except Exception:
                pass
                
            discovered.append({
                "username": username,
                "arn": arn,
                "mfa_enabled": mfa_enabled,
                "is_admin": is_admin,
                "access_keys_age_days": access_keys_age_days or 0,
                "last_active": user.get("PasswordLastUsed")
            })
    except Exception as e:
        print(f"Error listing IAM users: {e}")
    return discovered
