from typing import List, Dict, Any, Optional
from datetime import datetime
from botocore.exceptions import ClientError
from app.cloud.aws.collectors.base import BaseCollector

class SecurityGroupCollector(BaseCollector):
    """Security Group collector with relationship mapping"""
    
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.ec2_client = session.client('ec2', region_name=region)
        self.collector_name = "security_group"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect all security groups with their rules"""
        try:
            security_groups = []
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    normalized = await self._normalize_security_group(sg)
                    security_groups.append(normalized)
            
            return security_groups
            
        except ClientError:
            return []
        except Exception:
            return []
    
    async def _normalize_security_group(self, sg: Dict) -> Dict[str, Any]:
        """Normalize security group to Aegivion asset format"""
        
        # Parse ingress rules
        ingress_rules = []
        for rule in sg.get('IpPermissions', []):
            parsed = self._parse_rule(rule, 'ingress')
            if parsed:
                ingress_rules.extend(parsed)
        
        # Parse egress rules
        egress_rules = []
        for rule in sg.get('IpPermissionsEgress', []):
            parsed = self._parse_rule(rule, 'egress')
            if parsed:
                egress_rules.extend(parsed)
        
        # Check for internet exposure
        internet_exposure = self._check_internet_exposure(ingress_rules)
        
        return {
            "asset_id": f"sg:{sg['GroupId']}",
            "provider": "aws",
            "type": "security_group",
            "region": self.region,
            "name": sg.get('GroupName', sg['GroupId']),
            "configuration": {
                "group_id": sg['GroupId'],
                "group_name": sg.get('GroupName'),
                "description": sg.get('Description', ''),
                "vpc_id": sg.get('VpcId'),
                "owner_id": sg.get('OwnerId'),
                "ingress_rules": ingress_rules,
                "egress_rules": egress_rules,
                "has_internet_exposure": internet_exposure,
                "internet_exposure_details": self._get_exposure_details(ingress_rules)
            },
            "relationships": [
                {
                    "type": "belongs_to",
                    "target_id": sg.get('VpcId'),
                    "target_type": "vpc"
                }
            ] + self._get_security_group_references(sg)
        }
    
    def _parse_rule(self, rule: Dict, direction: str) -> List[Dict]:
        """Parse a security group rule into a consistent format"""
        rules = []
        
        ip_protocol = rule.get('IpProtocol', '-1')
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        
        # Parse IPv4 ranges
        for ip_range in rule.get('IpRanges', []):
            rules.append({
                "direction": direction,
                "protocol": ip_protocol,
                "from_port": from_port,
                "to_port": to_port,
                "source": ip_range.get('CidrIp'),
                "description": ip_range.get('Description', ''),
                "type": "ipv4"
            })
        
        # Parse IPv6 ranges
        for ip_range in rule.get('Ipv6Ranges', []):
            rules.append({
                "direction": direction,
                "protocol": ip_protocol,
                "from_port": from_port,
                "to_port": to_port,
                "source": ip_range.get('CidrIpv6'),
                "description": ip_range.get('Description', ''),
                "type": "ipv6"
            })
        
        # Parse referenced security groups
        for ref in rule.get('UserIdGroupPairs', []):
            rules.append({
                "direction": direction,
                "protocol": ip_protocol,
                "from_port": from_port,
                "to_port": to_port,
                "source": ref.get('GroupId'),
                "source_account": ref.get('UserId'),
                "description": ref.get('Description', ''),
                "type": "security_group_ref"
            })
        
        return rules
    
    def _check_internet_exposure(self, rules: List[Dict]) -> bool:
        """Check if any rule allows internet exposure"""
        for rule in rules:
            if rule.get('type') in ['ipv4', 'ipv6']:
                source = rule.get('source', '')
                if source == '0.0.0.0/0' or source == '::/0':
                    return True
        return False
    
    def _get_exposure_details(self, rules: List[Dict]) -> List[Dict]:
        """Get detailed internet exposure information"""
        exposed = []
        for rule in rules:
            if rule.get('type') in ['ipv4', 'ipv6']:
                source = rule.get('source', '')
                if source in ['0.0.0.0/0', '::/0']:
                    exposed.append({
                        "protocol": rule.get('protocol'),
                        "from_port": rule.get('from_port'),
                        "to_port": rule.get('to_port'),
                        "source": source,
                        "direction": rule.get('direction')
                    })
        return exposed
    
    def _get_security_group_references(self, sg: Dict) -> List[Dict]:
        """Extract security group references from rules"""
        references = []
        
        for rule in sg.get('IpPermissions', []):
            for ref in rule.get('UserIdGroupPairs', []):
                references.append({
                    "type": "references",
                    "target_id": ref.get('GroupId'),
                    "target_type": "security_group",
                    "metadata": {
                        "source_account": ref.get('UserId'),
                        "direction": "ingress"
                    }
                })
        
        return references
