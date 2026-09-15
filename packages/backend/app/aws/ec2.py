import boto3

def discover_ec2_instances(session=None) -> list:
    if session is None:
        return []
    ec2_client = session.client("ec2")
    discovered = []
    try:
        response = ec2_client.describe_instances()
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                inst_id = inst["InstanceId"]
                state = inst["State"]["Name"]
                public_ip = inst.get("PublicIpAddress")
                private_ip = inst.get("PrivateIpAddress")
                inst_type = inst["InstanceType"]
                sgs = inst.get("SecurityGroups", [])
                region = session.region_name
                
                discovered.append({
                    "instance_id": inst_id,
                    "state": state,
                    "public_ip": public_ip,
                    "private_ip": private_ip,
                    "instance_type": inst_type,
                    "security_groups": sgs,
                    "has_public_ip": public_ip is not None,
                    "region": region
                })
    except Exception as e:
        print(f"Error listing EC2 instances: {e}")
    return discovered
