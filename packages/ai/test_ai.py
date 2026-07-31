from app.config import AIConfig, get_vector_db_client
from app.prompts import get_remediation_prompt

def test_ai_config():
    assert AIConfig.LLM_PROVIDER in ["gemini", "openai", "azure"]
    client_info = get_vector_db_client()
    assert client_info["provider"] == "Qdrant"

def test_prompt_generation():
    prompt = get_remediation_prompt("S3 Public Access Enabled", "Bucket has public read ACLs", "aws_s3_bucket")
    assert "S3 Public Access Enabled" in prompt
    assert "aws_s3_bucket" in prompt
    assert "Terraform" in prompt
