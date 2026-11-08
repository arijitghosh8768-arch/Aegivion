import pytest
import os
from unittest.mock import MagicMock, patch
from ai.services.llm_provider import OpenAIProvider, GeminiProvider, LocalProvider, LLMResponse, get_llm_provider

def test_mock_fallback_when_keys_missing():
    """Verify that when no API keys are provided, providers gracefully fall back to mock response"""
    openai_provider = OpenAIProvider(api_key=None)
    res_openai = openai_provider.generate("Test prompt")
    assert isinstance(res_openai, LLMResponse)
    assert res_openai.provider == "openai"
    assert "tokens" in res_openai.to_dict()
    assert res_openai.tokens["total"] > 0
    assert res_openai.cost >= 0.0

    gemini_provider = GeminiProvider(api_key=None)
    res_gemini = gemini_provider.generate("Test prompt")
    assert isinstance(res_gemini, LLMResponse)
    assert res_gemini.provider == "gemini"
    assert "tokens" in res_gemini.to_dict()
    assert res_gemini.tokens["total"] > 0
    assert res_gemini.cost >= 0.0

    local_provider = LocalProvider()
    res_local = local_provider.generate("Test prompt")
    assert isinstance(res_local, LLMResponse)
    assert res_local.provider == "local"

def test_openai_real_call_mocked():
    """Verify that OpenAIProvider executes the openai client chat completion and parses token usage & cost"""
    provider = OpenAIProvider(api_key="test-sk-dummy-key-12345", model="gpt-4o-mini")

    mock_choice = MagicMock()
    mock_choice.message.content = '{"summary": "Real OpenAI response", "confidence_score": 0.95}'

    mock_usage = MagicMock()
    mock_usage.prompt_tokens = 150
    mock_usage.completion_tokens = 75
    mock_usage.total_tokens = 225

    mock_completion = MagicMock()
    mock_completion.choices = [mock_choice]
    mock_completion.usage = mock_usage

    mock_client_instance = MagicMock()
    mock_client_instance.chat.completions.create.return_value = mock_completion

    with patch("openai.OpenAI", return_value=mock_client_instance) as mock_openai_cls:
        response = provider.generate("Analyze vulnerable EC2", system_prompt="You are a security AI.")

        # Verify client instantiation with correct api_key
        mock_openai_cls.assert_called_once_with(api_key="test-sk-dummy-key-12345")

        # Verify chat completion call parameters
        mock_client_instance.chat.completions.create.assert_called_once_with(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security AI."},
                {"role": "user", "content": "Analyze vulnerable EC2"}
            ],
            temperature=0.2
        )

        assert isinstance(response, LLMResponse)
        assert response.text == '{"summary": "Real OpenAI response", "confidence_score": 0.95}'
        assert response.tokens["prompt"] == 150
        assert response.tokens["completion"] == 75
        assert response.tokens["total"] == 225
        assert response.cost > 0.0
        assert response.model == "gpt-4o-mini"
        assert response.provider == "openai"

def test_gemini_real_call_mocked():
    """Verify that GeminiProvider executes google.genai Client generate_content and parses usage metadata"""
    provider = GeminiProvider(api_key="test-gemini-key-9999", model="gemini-1.5-flash")

    mock_response = MagicMock()
    mock_response.text = '{"summary": "Real Gemini response", "confidence_score": 0.92}'

    mock_usage = MagicMock()
    mock_usage.prompt_token_count = 200
    mock_usage.candidates_token_count = 100
    mock_usage.total_token_count = 300
    mock_response.usage_metadata = mock_usage

    mock_client_instance = MagicMock()
    mock_client_instance.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client_instance) as mock_genai_cls:
        response = provider.generate("Analyze S3 bucket", system_prompt="Security instructions.")

        mock_genai_cls.assert_called_once_with(api_key="test-gemini-key-9999")
        mock_client_instance.models.generate_content.assert_called_once_with(
            model="gemini-1.5-flash",
            contents="System Instructions:\nSecurity instructions.\n\nUser Context:\nAnalyze S3 bucket"
        )

        assert isinstance(response, LLMResponse)
        assert response.text == '{"summary": "Real Gemini response", "confidence_score": 0.92}'
        assert response.tokens["prompt"] == 200
        assert response.tokens["completion"] == 100
        assert response.tokens["total"] == 300
        assert response.cost > 0.0
        assert response.provider == "gemini"

