import boto3

def discover_ec2_instances(session=None) -> list:
    if session is None:
        return [
            {
                "instance_id": "i-0987654321fedcba0",
                "state": "running",
                "public_ip": "54.210.12.34",
                "private_ip": "10.0.1.15",
                "instance_type": "t3.medium",
                "security_groups": [{"GroupId": "sg-12345678", "GroupName": "web-sg"}],
                "has_public_ip": True,
                "region": "ap-south-1"
            },
            {
                "instance_id": "i-0123456789abcdef0",
                "state": "stopped",
                "public_ip": None,
                "private_ip": "10.0.2.45",
                "instance_type": "t3.nano",
                "security_groups": [{"GroupId": "sg-87654321", "GroupName": "default"}],
                "has_public_ip": False,
                "region": "ap-south-1"
            }
        ]

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
