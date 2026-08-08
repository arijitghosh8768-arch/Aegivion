from typing import List, Dict, Any
from app.cloud.aws.collectors.base import BaseCollector
from botocore.exceptions import ClientError
from app.core.logging import logger

class VPCCollector(BaseCollector):
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.collector_name = "vpc"
        self.ec2_client = session.client('ec2', region_name=region)
        
    async def collect(self) -> List[Dict[str, Any]]:
        assets = []
        try:
            # 1. Describe VPCs
            vpcs_res = self.ec2_client.describe_vpcs()
            account_id = self.session.client('sts').get_caller_identity().get('Account', '123456789012')
            
            for vpc in vpcs_res.get('Vpcs', []):
                vpc_id = vpc['VpcId']
                vpc_arn = f"arn:aws:ec2:{self.region}:{account_id}:vpc/{vpc_id}"
                
                # Fetch route tables for relationships
                rts = []
                try:
                    rts_res = self.ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    rts = rts_res.get('RouteTables', [])
                except Exception:
                    pass
                
                # Fetch IGWs
                igws = []
                try:
                    igws_res = self.ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
                    igws = igws_res.get('InternetGateways', [])
                except Exception:
                    pass

                # Fetch NAT Gateways
                nats = []
                try:
                    nats_res = self.session.client('ec2', region_name=self.region).describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    nats = nats_res.get('NatGateways', [])
                except Exception:
                    pass
                
                relationships = []
                # IGW -> ATTACHED_TO -> VPC
                for igw in igws:
                    relationships.append({
                        "target_id": f"aws:igw:{igw['InternetGatewayId']}",
                        "type": "ATTACHED_TO",
                        "target_type": "internet_gateway",
                        "evidence": {"source": "ec2:describe_internet_gateways"}
                    })
                
                # Route Table relationships
                for rt in rts:
                    relationships.append({
                        "target_id": f"aws:route_table:{rt['RouteTableId']}",
                        "type": "ROUTES_TO",
                        "target_type": "route_table",
                        "evidence": {"routes": rt.get("Routes", [])}
                    })

                envelope = self._build_envelope(
                    asset_id=f"aws:vpc:{vpc_id}",
                    provider="aws",
                    account_id=account_id,
                    resource_type="vpc",
                    region=self.region,
                    arn=vpc_arn,
                    name=vpc_id,
                    configuration={
                        "cidr_block": vpc.get('CidrBlock'),
                        "state": vpc.get('State'),
                        "is_default": vpc.get('IsDefault', False)
                    },
                    relationships=relationships
                )
                assets.append(envelope.dict())
                
        except ClientError as e:
            logger.error(f"AWS client error in VPCCollector: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in VPCCollector: {e}")
            
        return assets

