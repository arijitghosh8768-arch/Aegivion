from typing import List, Dict, Any
from app.cloud.aws.collectors.base import BaseCollector
from botocore.exceptions import ClientError
from app.core.logging import logger

class SubnetCollector(BaseCollector):
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.collector_name = "subnet"
        self.ec2_client = session.client('ec2', region_name=region)
        
    async def collect(self) -> List[Dict[str, Any]]:
        assets = []
        try:
            subnets_res = self.ec2_client.describe_subnets()
            account_id = self.session.client('sts').get_caller_identity().get('Account', '123456789012')
            
            for subnet in subnets_res.get('Subnets', []):
                subnet_id = subnet['SubnetId']
                vpc_id = subnet['VpcId']
                subnet_arn = subnet.get('SubnetArn') or f"arn:aws:ec2:{self.region}:{account_id}:subnet/{subnet_id}"
                
                # Check route table connection to establish if it's public/private
                # Default is usually private unless it routes to IGW
                is_public = False
                rt_id = None
                try:
                    rts_res = self.ec2_client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
                    rts = rts_res.get('RouteTables', [])
                    if not rts:
                        # Fetch main RT for VPC as fallback
                        rts_res = self.ec2_client.describe_route_tables(Filters=[
                            {'Name': 'vpc-id', 'Values': [vpc_id]},
                            {'Name': 'association.main', 'Values': ['true']}
                        ])
                        rts = rts_res.get('RouteTables', [])
                    
                    if rts:
                        rt = rts[0]
                        rt_id = rt['RouteTableId']
                        for route in rt.get('Routes', []):
                            gateway_id = route.get('GatewayId', '')
                            if gateway_id.startswith('igw-'):
                                is_public = True
                except Exception:
                    pass

                relationships = [
                    {
                        "target_id": f"aws:vpc:{vpc_id}",
                        "type": "LOCATED_IN",
                        "target_type": "vpc",
                        "evidence": {"vpc_id": vpc_id}
                    }
                ]
                
                if rt_id:
                    relationships.append({
                        "target_id": f"aws:route_table:{rt_id}",
                        "type": "USES_ROUTE_TABLE",
                        "target_type": "route_table",
                        "evidence": {"route_table_id": rt_id}
                    })

                envelope = self._build_envelope(
                    asset_id=f"aws:subnet:{subnet_id}",
                    provider="aws",
                    account_id=account_id,
                    resource_type="subnet",
                    region=self.region,
                    arn=subnet_arn,
                    name=subnet_id,
                    configuration={
                        "vpc_id": vpc_id,
                        "cidr_block": subnet.get('CidrBlock'),
                        "available_ip_address_count": subnet.get('AvailableIpAddressCount'),
                        "map_public_ip_on_launch": subnet.get('MapPublicIpOnLaunch', False),
                        "public_reachability": "PUBLIC" if is_public else "PRIVATE"
                    },
                    relationships=relationships
                )
                assets.append(envelope.dict())
                
        except ClientError as e:
            logger.error(f"AWS client error in SubnetCollector: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in SubnetCollector: {e}")
            
        return assets

