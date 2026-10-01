import boto3

def discover_vpcs(session=None) -> list:
    if session is None:
        return []
        
    ec2_client = session.client("ec2")
    discovered = []
    try:
        response = ec2_client.describe_vpcs()
        for vpc in response.get("Vpcs", []):
            discovered.append({
                "vpc_id": vpc["VpcId"],
                "cidr_block": vpc.get("CidrBlock"),
                "is_default": vpc.get("IsDefault", False),
                "state": vpc.get("State"),
                "region": session.region_name
            })
    except Exception as e:
        print(f"Error listing VPCs: {e}")
    return discovered

def discover_security_groups(session=None) -> list:
    if session is None:
        return []
        
    ec2_client = session.client("ec2")
    discovered = []
    try:
        response = ec2_client.describe_security_groups()
        for sg in response.get("SecurityGroups", []):
            discovered.append({
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "description": sg.get("Description", ""),
                "vpc_id": sg.get("VpcId"),
                "region": session.region_name,
                "ip_permissions": sg.get("IpPermissions", []),
                "ip_permissions_egress": sg.get("IpPermissionsEgress", [])
            })
    except Exception as e:
        print(f"Error listing Security Groups: {e}")
    return discovered
