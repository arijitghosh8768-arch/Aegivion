import boto3
from botocore.exceptions import ClientError

def discover_iam_users(session=None) -> list:
    if session is None:
        return []
    
    iam_client = session.client("iam")
    discovered = []
    
    try:
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get("Users", []):
                mfa_active = False
                try:
                    mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
                    if mfa_devices.get('MFADevices'):
                        mfa_active = True
                except ClientError:
                    pass
                
                discovered.append({
                    "user_name": user["UserName"],
                    "arn": user["Arn"],
                    "user_id": user["UserId"],
                    "create_date": user["CreateDate"].isoformat(),
                    "mfa_active": mfa_active
                })
    except Exception as e:
        print(f"Error listing IAM users: {e}")
        
    return discovered

def discover_iam_roles(session=None) -> list:
    if session is None:
        return []
        
    iam_client = session.client("iam")
    discovered = []
    
    try:
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                discovered.append({
                    "role_name": role["RoleName"],
                    "arn": role["Arn"],
                    "role_id": role["RoleId"],
                    "create_date": role["CreateDate"].isoformat(),
                    "assume_role_policy": role.get("AssumeRolePolicyDocument")
                })
    except Exception as e:
        print(f"Error listing IAM roles: {e}")
        
    return discovered
