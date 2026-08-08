from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from botocore.exceptions import ClientError
import logging
from app.cloud.aws.collectors.base import BaseCollector, UNKNOWN

logger = logging.getLogger(__name__)

class IAMCollector(BaseCollector):
    """Hardened IAM collector with policy statement normalization"""
    
    def __init__(self, session, region: Optional[str] = None):
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
            
        except ClientError as e:
            logger.error(f"IAM collection failed: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"IAM collection failed: {str(e)}")
            return []
    
    async def _collect_users(self) -> List[Dict[str, Any]]:
        """Collect IAM users with security metadata"""
        users = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page.get('Users', []):
                try:
                    normalized = await self._normalize_user(user)
                    users.append(normalized)
                except ClientError as e:
                    logger.error(f"Failed to normalize user {user.get('UserName')}: {str(e)}")
                    continue
        
        return users
    
    async def _normalize_user(self, user: Dict) -> Dict[str, Any]:
        """Normalize IAM user with complete security metadata"""
        username = user['UserName']
        
        # Get security metadata
        groups = await self._get_user_groups(username)
        attached_policies = await self._get_attached_policies(username, 'user')
        inline_policies = await self._get_inline_policies(username, 'user')
        access_keys = await self._get_access_keys(username)
        mfa_enabled = await self._check_mfa(username)
        console_access = await self._check_console_access(username)
        
        # Get password last used
        password_last_used = user.get('PasswordLastUsed')
        
        # Calculate key metrics
        key_metrics = self._calculate_key_metrics(access_keys)
        
        is_admin_attached = any(
            p.get('name') == 'AdministratorAccess' or 'admin' in p.get('name', '').lower()
            for p in attached_policies
        )
        is_privileged = username.lower() == 'root' or is_admin_attached
        console_and_no_mfa = console_access and not mfa_enabled
        privileged_and_no_mfa = is_privileged and not mfa_enabled
        has_unused_active_key = any(
            k.get('status') == 'Active' and k.get('last_used', {}).get('status') == 'never_used'
            for k in access_keys
        )
        
        return {
            "asset_id": f"iam:user:{username}",
            "provider": "aws",
            "type": "iam_user",
            "resource_type": "iam_user",
            "region": "global",
            "name": username,
            "configuration": {
                "arn": user['Arn'],
                "user_id": user['UserId'],
                "created_date": user['CreateDate'].isoformat(),
                "console_access": console_access,
                "mfa_enabled": mfa_enabled,
                "password_last_used": password_last_used.isoformat() if password_last_used else None,
                "access_keys": access_keys,
                "access_key_count": len(access_keys),
                "active_key_count": sum(1 for k in access_keys if k.get('status') == 'Active'),
                "oldest_active_key_days": key_metrics.get('oldest_active_days'),
                "groups": groups,
                "attached_policies": attached_policies,
                "inline_policy_count": len(inline_policies),
                "is_privileged": is_privileged,
                "console_and_no_mfa": console_and_no_mfa,
                "privileged_and_no_mfa": privileged_and_no_mfa,
                "has_unused_active_key": has_unused_active_key
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

    async def _get_groups(self, username: str) -> List[str]:
        return await self._get_user_groups(username)

    async def _check_console_access(self, username: str) -> bool:
        return await self._has_console_access(username)
    
    async def _get_user_groups(self, username: str) -> List[str]:
        """Get groups for a user"""
        try:
            response = self.iam_client.list_groups_for_user(UserName=username)
            return [group['GroupName'] for group in response.get('Groups', [])]
        except ClientError:
            return []
    
    async def _get_attached_policies(self, username: str, target_type: str = 'user') -> List[Dict]:
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
    
    async def _get_inline_policies(self, username: str, target_type: str = 'user') -> List[str]:
        """Get inline policies for a user"""
        try:
            response = self.iam_client.list_user_policies(UserName=username)
            return response.get('PolicyNames', [])
        except ClientError:
            return []
    
    async def _get_access_keys(self, username: str) -> List[Dict[str, Any]]:
        """Get access keys with security metadata and unknown handling"""
        try:
            response = self.iam_client.list_access_keys(UserName=username)
            keys = []
            
            for key in response.get('AccessKeyMetadata', []):
                # Get last used data
                last_used = await self._get_key_last_used(key['AccessKeyId'])
                
                # Calculate age
                created_date = key['CreateDate']
                age_days = (datetime.utcnow() - created_date.replace(tzinfo=None)).days
                
                keys.append({
                    "access_key_id": self._mask_key_id(key['AccessKeyId']),
                    "status": key['Status'],
                    "created_at": created_date.isoformat(),
                    "age_days": age_days,
                    "last_used": last_used  # May be UNKNOWN
                })
            
            return keys
        except ClientError as e:
            logger.error(f"Failed to get access keys for {username}: {str(e)}")
            return []
    
    async def _get_key_last_used(self, access_key_id: str) -> Dict[str, Any]:
        """Get last used metadata with unknown handling"""
        try:
            response = self.iam_client.get_access_key_last_used(
                AccessKeyId=access_key_id
            )
            last_used_info = response.get('AccessKeyLastUsed', {})
            
            last_used_date = last_used_info.get('LastUsedDate')
            if last_used_date:
                return {
                    "last_used_at": last_used_date.isoformat(),
                    "last_used_service": last_used_info.get('ServiceName'),
                    "last_used_region": last_used_info.get('Region'),
                    "status": "known"
                }
            else:
                # Key exists but has never been used
                return {
                    "last_used_at": None,
                    "last_used_service": None,
                    "last_used_region": None,
                    "status": "never_used"
                }
        except ClientError as e:
            return {
                "last_used_at": None,
                "last_used_service": None,
                "last_used_region": None,
                "status": "unknown"
            }
    
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
            return False
    
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
                        "resource_type": "iam_role",
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
                        "resource_type": "iam_group",
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
                        normalized = await self._normalize_policy(policy)
                        if normalized:
                            policies.append(normalized)
                    except ClientError:
                        continue
        
        return policies
    
    async def _normalize_policy(self, policy: Dict) -> Dict[str, Any]:
        """Normalize policy with statement analysis"""
        try:
            # Get policy version
            version_response = self.iam_client.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )
            
            policy_document = version_response['PolicyVersion']['Document']
            
            # Analyze statements
            statements = self._analyze_policy_statements(policy_document)
            
            return {
                "asset_id": f"iam:policy:{policy['PolicyName']}",
                "provider": "aws",
                "type": "iam_policy",
                "resource_type": "iam_policy",
                "region": "global",
                "name": policy['PolicyName'],
                "configuration": {
                    "arn": policy['Arn'],
                    "policy_id": policy['PolicyId'],
                    "created_date": policy['CreateDate'].isoformat(),
                    "attachment_count": policy.get('AttachmentCount', 0),
                    "default_version_id": policy['DefaultVersionId'],
                    "statements": statements,
                    "is_admin_policy": self._is_admin_policy(statements),
                    "has_wildcard_actions": self._has_wildcard_actions(statements),
                    "has_wildcard_resources": self._has_wildcard_resources(statements),
                    "policy_document": policy_document
                }
            }
        except Exception as e:
            logger.error(f"Failed to normalize policy {policy.get('PolicyName')}: {str(e)}")
            return None
    
    def _analyze_policy_statements(self, policy_document: Dict) -> List[Dict]:
        """Analyze policy statements for security posture"""
        statements = []
        
        stmt = policy_document.get('Statement', [])
        if isinstance(stmt, dict):
            statements.append(self._analyze_statement(stmt))
        elif isinstance(stmt, list):
            for s in stmt:
                statements.append(self._analyze_statement(s))
        
        return statements
    
    def _analyze_statement(self, stmt: Dict) -> Dict:
        """Analyze a single policy statement"""
        effect = stmt.get('Effect', 'Deny')
        actions = self._normalize_actions(stmt.get('Action', []))
        resources = self._normalize_resources(stmt.get('Resource', []))
        principals = stmt.get('Principal', {})
        conditions = stmt.get('Condition', {})
        
        return {
            "effect": effect,
            "actions": actions,
            "resources": resources,
            "principals": principals,
            "conditions": conditions,
            "has_wildcard_action": '*' in actions if isinstance(actions, list) else actions == '*',
            "has_wildcard_resource": '*' in resources if isinstance(resources, list) else resources == '*',
            "is_public": self._is_public_statement(principals),
            "risk_level": self._assess_statement_risk(effect, actions, resources)
        }
        
    def _normalize_actions(self, action: Union[str, List[str]]) -> List[str]:
        if isinstance(action, list):
            return action
        return [action] if action else []

    def _normalize_resources(self, resource: Union[str, List[str]]) -> List[str]:
        if isinstance(resource, list):
            return resource
        return [resource] if resource else []

    def _is_public_statement(self, principals: Any) -> bool:
        if not principals:
            return False
        if principals == '*':
            return True
        if isinstance(principals, dict):
            if '*' in principals.values():
                return True
        return False

    def _assess_statement_risk(self, effect: str, actions: List[str], resources: List[str]) -> str:
        if effect == 'Deny':
            return 'low'
        has_wildcard_action = '*' in actions or any('*' in a for a in actions)
        has_wildcard_resource = '*' in resources or any('*' in r for r in resources)
        if has_wildcard_action and has_wildcard_resource:
            return 'high'
        if has_wildcard_action or has_wildcard_resource:
            return 'medium'
        return 'low'
    
    def _is_admin_policy(self, statements: List[Dict]) -> bool:
        """Check if policy grants administrative access"""
        for stmt in statements:
            if stmt.get('effect') == 'Allow':
                if stmt.get('has_wildcard_action') and stmt.get('has_wildcard_resource'):
                    return True
                if '*' in stmt.get('actions', []) and '*' in stmt.get('resources', []):
                    return True
        return False
    
    def _has_wildcard_actions(self, statements: List[Dict]) -> bool:
        """Check if policy has wildcard actions"""
        for stmt in statements:
            if stmt.get('effect') == 'Allow' and stmt.get('has_wildcard_action'):
                return True
        return False
    
    def _has_wildcard_resources(self, statements: List[Dict]) -> bool:
        """Check if policy has wildcard resources"""
        for stmt in statements:
            if stmt.get('effect') == 'Allow' and stmt.get('has_wildcard_resource'):
                return True
        return False
    
    def _calculate_key_metrics(self, access_keys: List[Dict]) -> Dict:
        """Calculate key security metrics"""
        active_keys = [k for k in access_keys if k.get('status') == 'Active']
        
        if not active_keys:
            return {'oldest_active_days': None}
        
        oldest = max(active_keys, key=lambda k: k.get('age_days', 0))
        return {'oldest_active_days': oldest.get('age_days')}
    
    def _mask_key_id(self, key_id: str) -> str:
        """Mask access key ID for UI"""
        if len(key_id) > 8:
            return f"{key_id[:4]}***{key_id[-4:]}"
        return key_id
