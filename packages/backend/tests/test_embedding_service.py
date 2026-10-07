import pytest
import numpy as np
from app.services.embedding_service import LocalEmbeddingService, EmbeddingServiceFailure

def test_initialization():
    service = LocalEmbeddingService()
    assert service.model_name == "BAAI/bge-small-en-v1.5"
    assert service.dimension == 384
    assert service._loaded is False

def test_embed_empty_input():
    service = LocalEmbeddingService()
    res = service.embed_chunks([])
    assert res == []
    # Should not load model for empty input
    assert service._loaded is False

# Real integration tests, skip if sentence_transformers cannot be imported
try:
    import sentence_transformers
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

@pytest.mark.skipif(not HAS_SENTENCE_TRANSFORMERS, reason="sentence-transformers not installed or model unavailable")
def test_real_embedding_generation():
    service = LocalEmbeddingService()
    
    # 1. Test model loads
    service.load_model()
    assert service._loaded is True
    assert service._model is not None
    
    # 2. Test generating embeddings
    texts = ["SQL injection attack", "Cross site scripting XSS"]
    embeddings = service.embed_chunks(texts, batch_size=2)
    
    assert len(embeddings) == 2
    
    # 3. Test dimension = 384
    assert len(embeddings[0]) == 384
    assert len(embeddings[1]) == 384
    
    # 4. Test deterministic output
    embeddings2 = service.embed_chunks(texts, batch_size=2)
    assert np.allclose(embeddings[0], embeddings2[0])
    
    # 5. Test L2 normalization (||embedding|| ≈ 1)
    norm1 = np.linalg.norm(embeddings[0])
    norm2 = np.linalg.norm(embeddings[1])
    assert np.isclose(norm1, 1.0, atol=1e-5)
    assert np.isclose(norm2, 1.0, atol=1e-5)

@pytest.mark.skipif(not HAS_SENTENCE_TRANSFORMERS, reason="sentence-transformers not installed")
def test_embedding_failure_handling():
    service = LocalEmbeddingService()
    service.load_model()
    
    with pytest.raises(EmbeddingServiceFailure):
        # Pass an invalid type to force a failure inside sentence_transformers
        service.embed_chunks([None])
