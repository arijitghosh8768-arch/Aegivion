from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from botocore.exceptions import ClientError
import logging
from app.cloud.aws.collectors.base import BaseCollector, UNKNOWN

logger = logging.getLogger(__name__)

@dataclass
class NetworkRule:
    """Normalized network rule representation"""
    protocol: str
    from_port: Optional[int]
    to_port: Optional[int]
    source_type: str  # 'ipv4', 'ipv6', 'security_group'
    source_value: str
    direction: str  # 'ingress', 'egress'
    description: str
    is_public: bool
    is_ipv6: bool
    
    def is_internet_exposed(self) -> bool:
        """Check if rule exposes to internet"""
        if self.source_type in ['ipv4', 'ipv6']:
            if self.source_value in ['0.0.0.0/0', '::/0']:
                return True
        return False

class SecurityGroupCollector(BaseCollector):
    """Enhanced Security Group collector with IPv6 support"""
    
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.ec2_client = session.client('ec2', region_name=region)
        self.collector_name = "security_group"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect security groups with full rule details"""
        try:
            security_groups = []
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    normalized = await self._normalize_sg(sg)
                    security_groups.append(normalized)
            
            logger.info(f"Collected {len(security_groups)} security groups from {self.region}")
            return security_groups
            
        except ClientError as e:
            if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
                logger.error(f"Access denied for security groups in {self.region}")
                return []
            logger.error(f"Security group collection failed: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Security group collection failed: {str(e)}")
            return []
    
    async def _normalize_sg(self, sg: Dict) -> Dict[str, Any]:
        """Normalize security group with full rule details"""
        
        # Parse all rules
        ingress_rules = await self._parse_rules(sg.get('IpPermissions', []), 'ingress')
        egress_rules = await self._parse_rules(sg.get('IpPermissionsEgress', []), 'egress')
        
        # Check exposure
        internet_exposed = any(r.is_internet_exposed() for r in ingress_rules)
        ipv6_exposed = any(r.is_ipv6 and r.is_internet_exposed() for r in ingress_rules)
        
        # Get exposed protocols/ports
        exposed_services = await self._identify_exposed_services(ingress_rules)
        
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
                "ingress_rules": [asdict(r) for r in ingress_rules],
                "egress_rules": [asdict(r) for r in egress_rules],
                "internet_exposed": internet_exposed,
                "ipv6_exposed": ipv6_exposed,
                "exposed_services": exposed_services,
                "has_all_traffic": any(
                    r.protocol == '-1' and r.is_internet_exposed()
                    for r in ingress_rules
                ),
                "has_all_tcp": any(
                    r.protocol == 'tcp' and 
                    r.from_port == 0 and 
                    r.to_port == 65535 and 
                    r.is_internet_exposed()
                    for r in ingress_rules
                )
            },
            "relationships": [
                {
                    "type": "belongs_to",
                    "target_id": sg.get('VpcId'),
                    "target_type": "vpc"
                }
            ],
            "metadata": {
                "collected_at": datetime.utcnow().isoformat(),
                "collector_version": "2.0.0"
            }
        }
    
    async def _parse_rules(self, rules: List[Dict], direction: str) -> List[NetworkRule]:
        """Parse security group rules with full detail"""
        parsed = []
        
        for rule in rules:
            protocol = rule.get('IpProtocol', '-1')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            
            # Parse IPv4 ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                parsed.append(NetworkRule(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source_type="ipv4",
                    source_value=cidr,
                    direction=direction,
                    description=ip_range.get('Description', ''),
                    is_public=cidr == '0.0.0.0/0',
                    is_ipv6=False
                ))
            
            # Parse IPv6 ranges
            for ip_range in rule.get('Ipv6Ranges', []):
                cidr = ip_range.get('CidrIpv6')
                parsed.append(NetworkRule(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source_type="ipv6",
                    source_value=cidr,
                    direction=direction,
                    description=ip_range.get('Description', ''),
                    is_public=cidr == '::/0',
                    is_ipv6=True
                ))
            
            # Parse referenced security groups
            for ref in rule.get('UserIdGroupPairs', []):
                parsed.append(NetworkRule(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source_type="security_group",
                    source_value=ref.get('GroupId'),
                    direction=direction,
                    description=ref.get('Description', ''),
                    is_public=False,
                    is_ipv6=False
                ))
        
        return parsed
    
    async def _identify_exposed_services(self, rules: List[NetworkRule]) -> List[Dict]:
        """Identify exposed services from rules"""
        service_map = {
            22: {'name': 'SSH', 'severity': 'high'},
            3389: {'name': 'RDP', 'severity': 'high'},
            3306: {'name': 'MySQL', 'severity': 'medium'},
            5432: {'name': 'PostgreSQL', 'severity': 'medium'},
            27017: {'name': 'MongoDB', 'severity': 'medium'},
            6379: {'name': 'Redis', 'severity': 'medium'},
            9200: {'name': 'Elasticsearch', 'severity': 'medium'},
            1433: {'name': 'MSSQL', 'severity': 'medium'}
        }
        
        exposed = []
        for rule in rules:
            if rule.is_public and rule.protocol == 'tcp':
                port = rule.to_port
                if port in service_map:
                    exposed.append({
                        'port': port,
                        'service': service_map[port]['name'],
                        'severity': service_map[port]['severity']
                    })
        
        return exposed
