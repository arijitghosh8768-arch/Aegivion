from typing import List, Dict, Any

class PrivilegeEscalationRule:
    """
    Rule to detect identity privilege escalation paths.
    
    WHY IT EXISTS:
    Identity and Access Management (IAM) configurations can often contain complex 
    relationship webs. A common security risk occurs when an unprivileged user 
    has the ability to assume a role that has significantly higher privileges, 
    such as AdministratorAccess. This rule exists to identify these hidden paths 
    before they can be exploited.
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    If an attacker compromises the credentials of a low-privileged user, they 
    could exploit this path to assume the highly privileged role. This leads to 
    full system compromise, data exfiltration, or complete loss of control over 
    the cloud environment.
    """
    
    def evaluate(self, assets: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        
        iam_users = [a for a in assets if a.get('type') == 'iam_user']
        roles = {a['asset_id']: a for a in assets if a.get('type') == 'iam_role'}
        
        for user in iam_users:
            user_id = user['asset_id']
            # Find roles this user can assume
            can_assume = [r for r in relationships if r.get('source_asset_id') == user_id and r.get('relationship_type') == 'can_assume']
            
            for rel in can_assume:
                target_role_id = rel.get('target_asset_id')
                role = roles.get(target_role_id)
                if role:
                    # Check if role has Admin access
                    policies = role.get('configuration', {}).get('attached_policies', [])
                    for p in policies:
                        if 'AdministratorAccess' in p.get('policy_name', ''):
                            findings.append({
                                'rule_id': 'privilege_escalation_path',
                                'title': f'Privilege Escalation Path: {user.get("name", user_id)} -> {role.get("name", target_role_id)}',
                                'description': f'User {user.get("name", user_id)} can assume role {role.get("name", target_role_id)} which has AdministratorAccess.',
                                'severity': 'HIGH',
                                'asset_id': user_id,
                                'category': 'PRIVILEGE_ESCALATION',
                                'metadata': {
                                    'target_role': role.get("name", target_role_id),
                                    'escalation_hops': 1
                                }
                            })
                            
        return findings

class LateralMovementRule:
    """
    Rule to detect lateral movement risk (broad internal outbound).
    
    WHY IT EXISTS:
    Security groups should follow the principle of least privilege. When an instance 
    has unrestricted outbound access (0.0.0.0/0), it means that if the instance is 
    compromised, it can connect to any internal or external IP address. This rule 
    exists to detect instances that could be used as a jumping-off point to attack 
    other resources in the network.
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    An attacker who breaches this instance can easily perform network scanning, 
    communicate with command-and-control (C2) servers, or move laterally to other 
    sensitive internal services (e.g., databases, internal APIs) without network-level 
    restrictions blocking their path.
    """
    
    def evaluate(self, assets: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        
        ec2_instances = [a for a in assets if a.get('type') in ['ec2_instance', 'ec2']]
        sgs = {a['asset_id']: a for a in assets if a.get('type') in ['security_group', 'sg']}
        
        for ec2 in ec2_instances:
            ec2_id = ec2['asset_id']
            # Check attached SGs
            attached_sgs = [r.get('target_asset_id') for r in relationships if r.get('source_asset_id') == ec2_id and r.get('relationship_type') == 'protected_by']
            
            for sg_id in attached_sgs:
                sg = sgs.get(sg_id)
                if sg:
                    egress = sg.get('configuration', {}).get('egress_rules', [])
                    for rule in egress:
                        if rule.get('ip_protocol') == '-1' and rule.get('cidr_ipv4') == '0.0.0.0/0':
                            findings.append({
                                'rule_id': 'lateral_movement_broad_egress',
                                'title': f'Lateral Movement Risk: Broad Egress on {ec2.get("name", ec2_id)}',
                                'description': 'Instance is attached to a Security Group allowing unrestricted outbound access, facilitating lateral movement if compromised.',
                                'severity': 'MEDIUM',
                                'asset_id': ec2_id,
                                'category': 'LATERAL_MOVEMENT',
                                'metadata': {
                                    'sg_id': sg_id
                                }
                            })
                            break
                            
        return findings
