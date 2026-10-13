# API and Integration Contracts

## Rules
- Treat current route schemas/OpenAPI as source of truth until audited.
- Document method, path, request/response, auth, role, tenant scope, errors, pagination, idempotency, rate limits, and consumers.
- Do not change public fields without reviewing consumers and tests.
- Never return provider secrets or raw credential payloads.
- Derive organization scope from verified server-side membership.

## Conceptual asset example
```json
{
  "asset_id": "asset-001",
  "provider": "aws",
  "type": "ec2",
  "region": "ap-south-1",
  "name": "web-server",
  "configuration": {},
  "relationships": []
}
```

## Conceptual finding example
```json
{
  "finding_id": "F-001",
  "asset_id": "asset-001",
  "rule_id": "AWS-NET-001",
  "title": "SSH exposed to internet",
  "severity": "critical",
  "risk_score": 92,
  "evidence": {"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}
}
```

## Conceptual AI response
```json
{
  "finding_id": "F-001",
  "root_cause": "Evidence-grounded explanation",
  "technical_impact": "Qualified technical impact",
  "business_impact": "Impact with assumptions stated",
  "recommendations": [],
  "confidence": 0.0
}
```

These examples are conceptual, not guaranteed current wire schemas. Verify actual schemas before implementation.
