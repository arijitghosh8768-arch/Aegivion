import boto3

def discover_security_groups(session=None) -> list:
    if session is None:
        return [
            {
                "group_id": "sg-12345678",
                "group_name": "web-sg",
                "vpc_id": "vpc-011223344",
                "ingress_rules": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ],
                "egress_rules": [],
                "region": "ap-south-1"
            },
            {
                "group_id": "sg-87654321",
                "group_name": "internal-sg",
                "vpc_id": "vpc-011223344",
                "ingress_rules": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
                    }
                ],
                "egress_rules": [],
                "region": "ap-south-1"
            }
        ]

    ec2 = session.client("ec2")
    discovered = []
    try:
        response = ec2.describe_security_groups()
        for sg in response.get("SecurityGroups", []):
            discovered.append({
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "vpc_id": sg.get("VpcId"),
                "ingress_rules": sg.get("IpPermissions", []),
                "egress_rules": sg.get("IpPermissionsEgress", []),
                "region": session.region_name
            })
    except Exception as e:
        print(f"Error listing security groups: {e}")
    return discovered
