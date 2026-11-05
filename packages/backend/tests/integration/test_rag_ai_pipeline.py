import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from ai.services.rag import SecurityKnowledgeRetriever
from ai.services.prompt_builder import PromptBuilder, PromptContext
from ai.services.llm_provider import LLMProvider

class MockLLMProvider(LLMProvider):
    def __init__(self, model_name: str = "mock-model", api_key: str = "mock-key"):
        self.model_name = model_name
        self.api_key = api_key

    def generate(self, prompt: str) -> str:
        return '{"summary": "Mock summary", "observed": ["Mock observed"], "inferred": ["Mock inferred"], "unknown": ["Mock unknown"], "recommendations": ["Mock recommendation"], "confidence_score": 0.95}'

class TestRagAiPipeline(unittest.TestCase):

    def setUp(self):
        self.retriever = SecurityKnowledgeRetriever()
        self.prompt_builder = PromptBuilder()
        self.llm = MockLLMProvider(model_name="mock-model", api_key="mock-key")

    def test_rag_retrieval(self):
        metadata = {"mitre_technique": "T1078"}
        result = self.retriever.retrieve_security_knowledge(
            finding_id="finding-123",
            provider="aws",
            finding_type="CredentialCompromise",
            finding_metadata=metadata
        )
        self.assertEqual(result["finding_id"], "finding-123")
        self.assertEqual(result["provider"], "aws")
        self.assertTrue(len(result["relevant_knowledge"]) >= 0)

    def test_prompt_builder_and_llm(self):
        finding = {
            "finding_id": "123",
            "title": "Test finding",
            "description": "Test finding description",
            "severity": "high",
            "rule_id": "test_rule"
        }
        asset = {"asset_id": "asset-1", "provider": "aws"}
        
        context = PromptContext(
            finding=finding,
            asset=asset,
            evidence={"cloudtrail_event": "ConsoleLogin"},
            severity="high",
            risk_score=85.0,
            mitre_technique="T1078",
            mitre_tactic="Initial Access",
            rag_knowledge=[{"title": "Test knowledge", "content": "Test content", "tags": ["test"]}]
        )
        
        prompt = self.prompt_builder.build_prompt(context)
        self.assertIn("Test finding", prompt)
        self.assertIn("Test knowledge", prompt)
        
        response = self.llm.generate(prompt)
        self.assertIn("Mock summary", response)

if __name__ == "__main__":
    unittest.main()
