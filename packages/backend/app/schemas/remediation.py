import re
from typing import Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator


class EnableS3PublicAccessBlockSchema(BaseModel):
    bucket_name: str = Field(..., min_length=3, max_length=63, description="Target S3 bucket name")
    BlockPublicAcls: bool = Field(True, description="Block public ACLs")
    IgnorePublicAcls: bool = Field(True, description="Ignore public ACLs")
    BlockPublicPolicy: bool = Field(True, description="Block public policy")
    RestrictPublicBuckets: bool = Field(True, description="Restrict public buckets")

    @field_validator("bucket_name")
    @classmethod
    def validate_bucket_name(cls, v: str) -> str:
        clean = v.strip().lower()
        # S3 bucket naming rules
        if not re.match(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", clean):
            raise ValueError(f"Invalid S3 bucket name format: '{v}'")
        if ".." in clean or ".-" in clean or "-." in clean:
            raise ValueError(f"S3 bucket name contains invalid character sequences: '{v}'")
        return clean

    @field_validator("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    @classmethod
    def must_be_true(cls, v: bool, info) -> bool:
        if v is not True:
            raise ValueError(f"Safety restriction: Parameter '{info.field_name}' must be explicitly True to enable public access protection.")
        return True


class RevokeSecurityGroupIngressSchema(BaseModel):
    group_id: str = Field(..., description="Target AWS Security Group ID (sg-...)")
    protocol: Literal["tcp", "udp", "icmp", "-1"] = Field("tcp", description="IP Protocol")
    from_port: int = Field(..., ge=-1, le=65535, description="Start of port range")
    to_port: int = Field(..., ge=-1, le=65535, description="End of port range")
    cidr_ip: str = Field(..., description="Unrestricted CIDR to revoke, strictly '0.0.0.0/0' or '::/0'")

    @field_validator("group_id")
    @classmethod
    def validate_group_id(cls, v: str) -> str:
        clean = v.strip()
        if not re.match(r"^sg-[a-f0-9]{8,17}$", clean):
            raise ValueError(f"Invalid AWS Security Group ID format: '{v}'. Expected sg-xxxxxxxx.")
        return clean

    @field_validator("to_port")
    @classmethod
    def validate_port_range(cls, v: int, info) -> int:
        from_port = info.data.get("from_port")
        if from_port is not None and v < from_port:
            raise ValueError(f"to_port ({v}) cannot be less than from_port ({from_port})")
        return v

    @field_validator("cidr_ip")
    @classmethod
    def validate_unrestricted_cidr(cls, v: str) -> str:
        clean = v.strip()
        allowed_cidrs = {"0.0.0.0/0", "::/0"}
        if clean not in allowed_cidrs:
            raise ValueError(
                f"Safety restriction: Automated ingress revocation is strictly permitted for unrestricted internet CIDRs ({allowed_cidrs}). Received '{v}'."
            )
        return clean

