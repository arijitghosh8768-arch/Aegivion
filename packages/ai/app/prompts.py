def get_remediation_prompt(finding_title: str, description: str, resource_type: str) -> str:
    """
    Generates a prompt for the LLM to write a comprehensive security remediation guide.
    """
    return f"""You are Aegivion's expert security AI assistant.
Analyze the following security finding and generate a clear, step-by-step remediation guide.

Finding: {finding_title}
Resource Type: {resource_type}
Details: {description}

Please provide:
1. Risk explanation (Why this matters)
2. Immediate CLI/API command to fix it
3. Infrastructure-as-code (Terraform/CloudFormation) template snippet to prevent it in the future.
4. Additional hardening recommendations.
"""
