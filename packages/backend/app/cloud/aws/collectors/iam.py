from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import asyncio
from botocore.exceptions import ClientError
from app.cloud.aws.collectors.base import BaseCollector

class IAMCollector(BaseCollector):
    """IAM security posture collector - no modifications to AWS"""
    
    def __init__(self, session):
        super().__init__(session, "global")
        self.iam_client = session.client('iam')
        self.collector_name = "iam"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect IAM security posture data"""
        try:
            assets = []
            
            # Collect users with pagination
            users = await self._collect_users()
            assets.extend(users)
            
            # Collect roles
            roles = await self._collect_roles()
            assets.extend(roles)
            
            # Collect groups
            groups = await self._collect_groups()
            assets.extend(groups)
            
            # Collect policies
            policies = await self._collect_policies()
            assets.extend(policies)
            
            return assets
            
        except ClientError:
            return []
        except Exception:
            return []
    
    async def _collect_users(self) -> List[Dict[str, Any]]:
        """Collect IAM users with security metadata"""
        users = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page.get('Users', []):
                username = user['UserName']
                
                try:
                    # Get user's groups
                    groups = await self._get_user_groups(username)
                    
                    # Get user's policies
                    attached_policies = await self._get_attached_policies(username)
                    inline_policies = await self._get_inline_policies(username)
                    
                    # Get access keys
                    access_keys = await self._get_access_keys(username)
                    
                    # Check MFA status
                    mfa_enabled = await self._check_mfa(username)
                    
                    # Get password last used
                    password_last_used = user.get('PasswordLastUsed')
                    
                    # Determine console access
                    console_access = await self._has_console_access(username)
                    
                    # Check if user is root (AWS root user doesn't appear in list_users generally, but we check name pattern or metadata)
                    is_root = username.lower() == 'root'
                    
                    # Normalize user
                    normalized = {
                        "asset_id": f"iam:user:{username}",
                        "provider": "aws",
                        "type": "iam_user",
                        "region": "global",
                        "name": username,
                        "configuration": {
                            "arn": user['Arn'],
                            "user_id": user['UserId'],
                            "created_date": user['CreateDate'].isoformat(),
                            "password_last_used": password_last_used.isoformat() if password_last_used else None,
                            "console_access": console_access,
                            "mfa_enabled": mfa_enabled,
                            "is_root_user": is_root,
                            "access_key_count": len(access_keys),
                            "access_keys": access_keys,
                            "groups": groups,
                            "attached_policies": attached_policies,
                            "inline_policy_count": len(inline_policies)
                        },
                        "relationships": [
                            {
                                "type": "member_of",
                                "target_id": f"iam:group:{group}",
                                "target_type": "iam_group"
                            }
                            for group in groups
                        ] + [
                            {
                                "type": "has_policy",
                                "target_id": policy['arn'],
                                "target_type": "iam_policy"
                            }
                            for policy in attached_policies
                        ]
                    }
                    users.append(normalized)
                    
                except ClientError:
                    continue
        
        return users
    
    async def _get_user_groups(self, username: str) -> List[str]:
        """Get groups for a user"""
        try:
            response = self.iam_client.list_groups_for_user(UserName=username)
            return [group['GroupName'] for group in response.get('Groups', [])]
        except ClientError:
            return []
    
    async def _get_attached_policies(self, username: str) -> List[Dict]:
        """Get attached policies for a user"""
        try:
            response = self.iam_client.list_attached_user_policies(UserName=username)
            return [
                {
                    'arn': policy['PolicyArn'],
                    'name': policy['PolicyName']
                }
                for policy in response.get('AttachedPolicies', [])
            ]
        except ClientError:
            return []
    
    async def _get_inline_policies(self, username: str) -> List[str]:
        """Get inline policies for a user"""
        try:
            response = self.iam_client.list_user_policies(UserName=username)
            return response.get('PolicyNames', [])
        except ClientError:
            return []
    
    async def _get_access_keys(self, username: str) -> List[Dict]:
        """Get access keys with security metadata"""
        try:
            response = self.iam_client.list_access_keys(UserName=username)
            keys = []
            
            for key in response.get('AccessKeyMetadata', []):
                # Get last used data if available
                last_used = None
                try:
                    used_response = self.iam_client.get_access_key_last_used(
                        AccessKeyId=key['AccessKeyId']
                    )
                    if 'AccessKeyLastUsed' in used_response:
                        last_used_info = used_response['AccessKeyLastUsed']
                        last_used = {
                            'last_used_date': last_used_info.get('LastUsedDate').isoformat() if last_used_info.get('LastUsedDate') else None,
                            'last_used_service': last_used_info.get('ServiceName'),
                            'last_used_region': last_used_info.get('Region')
                        }
                except ClientError:
                    pass
                
                # Calculate key age
                created_date = key['CreateDate']
                age_days = (datetime.utcnow() - created_date.replace(tzinfo=None)).days
                
                keys.append({
                    'access_key_id': key['AccessKeyId'][:4] + '***' + key['AccessKeyId'][-4:],
                    'status': key['Status'],
                    'created_date': created_date.isoformat(),
                    'age_days': age_days,
                    'last_used': last_used
                })
            
            return keys
        except ClientError:
            return []
    
    async def _check_mfa(self, username: str) -> bool:
        """Check if user has MFA enabled"""
        try:
            response = self.iam_client.list_mfa_devices(UserName=username)
            return len(response.get('MFADevices', [])) > 0
        except ClientError:
            return False
    
    async def _has_console_access(self, username: str) -> bool:
        """Check if user has console access (has login profile)"""
        try:
            response = self.iam_client.get_login_profile(UserName=username)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return False
            raise
    
    async def _collect_roles(self) -> List[Dict[str, Any]]:
        """Collect IAM roles"""
        roles = []
        paginator = self.iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                try:
                    role_name = role['RoleName']
                    
                    # Get attached policies
                    attached_policies = await self._get_role_policies(role_name)
                    
                    # Get inline policies
                    inline_policies = await self._get_role_inline_policies(role_name)
                    
                    normalized = {
                        "asset_id": f"iam:role:{role_name}",
                        "provider": "aws",
                        "type": "iam_role",
                        "region": "global",
                        "name": role_name,
                        "configuration": {
                            "arn": role['Arn'],
                            "role_id": role['RoleId'],
                            "created_date": role['CreateDate'].isoformat(),
                            "max_session_duration": role.get('MaxSessionDuration', 3600),
                            "attached_policies": attached_policies,
                            "inline_policy_count": len(inline_policies),
                            "trust_policy": role.get('AssumeRolePolicyDocument')
                        },
                        "relationships": [
                            {
                                "type": "has_policy",
                                "target_id": policy['arn'],
                                "target_type": "iam_policy"
                            }
                            for policy in attached_policies
                        ]
                    }
                    roles.append(normalized)
                    
                except ClientError:
                    continue
        
        return roles
    
    async def _get_role_policies(self, role_name: str) -> List[Dict]:
        """Get attached policies for a role"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            return [
                {
                    'arn': policy['PolicyArn'],
                    'name': policy['PolicyName']
                }
                for policy in response.get('AttachedPolicies', [])
            ]
        except ClientError:
            return []
    
    async def _get_role_inline_policies(self, role_name: str) -> List[str]:
        """Get inline policies for a role"""
        try:
            response = self.iam_client.list_role_policies(RoleName=role_name)
            return response.get('PolicyNames', [])
        except ClientError:
            return []
    
    async def _collect_groups(self) -> List[Dict[str, Any]]:
        """Collect IAM groups"""
        groups = []
        paginator = self.iam_client.get_paginator('list_groups')
        
        for page in paginator.paginate():
            for group in page.get('Groups', []):
                group_name = group['GroupName']
                
                try:
                    # Get attached policies
                    attached_policies = await self._get_group_policies(group_name)
                    
                    normalized = {
                        "asset_id": f"iam:group:{group_name}",
                        "provider": "aws",
                        "type": "iam_group",
                        "region": "global",
                        "name": group_name,
                        "configuration": {
                            "arn": group['Arn'],
                            "group_id": group['GroupId'],
                            "created_date": group['CreateDate'].isoformat(),
                            "attached_policies": attached_policies
                        },
                        "relationships": [
                            {
                                "type": "has_policy",
                                "target_id": policy['arn'],
                                "target_type": "iam_policy"
                            }
                            for policy in attached_policies
                        ]
                    }
                    groups.append(normalized)
                    
                except ClientError:
                    continue
        
        return groups
    
    async def _get_group_policies(self, group_name: str) -> List[Dict]:
        """Get attached policies for a group"""
        try:
            response = self.iam_client.list_attached_group_policies(GroupName=group_name)
            return [
                {
                    'arn': policy['PolicyArn'],
                    'name': policy['PolicyName']
                }
                for policy in response.get('AttachedPolicies', [])
            ]
        except ClientError:
            return []
    
    async def _collect_policies(self) -> List[Dict[str, Any]]:
        """Collect IAM policies"""
        policies = []
        paginator = self.iam_client.get_paginator('list_policies')
        
        for page in paginator.paginate(Scope='Local'):
            for policy in page.get('Policies', []):
                if policy.get('AttachmentCount', 0) > 0:
                    try:
                        # Get policy version
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        policy_document = version_response['PolicyVersion']['Document']
                        
                        # Analyze policy for security posture
                        is_admin = self._check_admin_policy(policy_document)
                        has_wildcard = self._check_wildcard_policy(policy_document)
                        
                        normalized = {
                            "asset_id": f"iam:policy:{policy['PolicyName']}",
                            "provider": "aws",
                            "type": "iam_policy",
                            "region": "global",
                            "name": policy['PolicyName'],
                            "configuration": {
                                "arn": policy['Arn'],
                                "policy_id": policy['PolicyId'],
                                "created_date": policy['CreateDate'].isoformat(),
                                "attachment_count": policy.get('AttachmentCount', 0),
                                "default_version_id": policy['DefaultVersionId'],
                                "is_admin_policy": is_admin,
                                "has_wildcard_permissions": has_wildcard,
                                "policy_document": policy_document
                            }
                        }
                        policies.append(normalized)
                        
                    except ClientError:
                        continue
        
        return policies
    
    def _check_admin_policy(self, policy_document: Dict) -> bool:
        """Check if policy has admin-level permissions"""
        try:
            for statement in policy_document.get('Statement', []):
                effect = statement.get('Effect', '')
                action = statement.get('Action', [])
                resource = statement.get('Resource', [])
                
                if effect == 'Allow':
                    # Check actions
                    actions_list = action if isinstance(action, list) else [action]
                    has_wildcard_action = '*' in actions_list or 'AdministratorAccess' in actions_list
                    
                    # Check resources
                    resources_list = resource if isinstance(resource, list) else [resource]
                    has_wildcard_resource = '*' in resources_list
                    
                    if has_wildcard_action and has_wildcard_resource:
                        return True
            return False
        except Exception:
            return False
    
    def _check_wildcard_policy(self, policy_document: Dict) -> Dict:
        """Check for wildcard permissions with evidence"""
        wildcard_actions = []
        wildcard_resources = []
        
        try:
            for statement in policy_document.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    
                    actions_list = actions if isinstance(actions, list) else [actions]
                    resources_list = resources if isinstance(resources, list) else [resources]
                    
                    for a in actions_list:
                        if '*' in str(a):
                            wildcard_actions.append(str(a))
                    for r in resources_list:
                        if '*' in str(r):
                            wildcard_resources.append(str(r))
            
            return {
                'has_wildcard_actions': len(wildcard_actions) > 0,
                'has_wildcard_resources': len(wildcard_resources) > 0,
                'wildcard_actions': wildcard_actions,
                'wildcard_resources': wildcard_resources
            }
        except Exception:
            return {
                'has_wildcard_actions': False,
                'has_wildcard_resources': False
            }
