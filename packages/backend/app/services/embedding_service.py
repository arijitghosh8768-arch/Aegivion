import logging
from typing import List
import numpy as np

logger = logging.getLogger(__name__)

class EmbeddingServiceFailure(Exception):
    pass

class LocalEmbeddingService:
    def __init__(self):
        self.model_name = "BAAI/bge-small-en-v1.5"
        self.dimension = 384
        self.max_tokens = 512
        self._model = None
        self._loaded = False
        
    def load_model(self):
        if self._loaded:
            return
        try:
            # Lazy import to avoid slowing down startup if embeddings aren't used
            from sentence_transformers import SentenceTransformer
            
            logger.info(f"Loading local embedding model: {self.model_name}")
            # Loading model with normalized embeddings by default if needed, 
            # or doing it manually during generation.
            self._model = SentenceTransformer(self.model_name)
            self._loaded = True
            logger.info("Local embedding model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            raise EmbeddingServiceFailure(f"Failed to load model {self.model_name}: {str(e)}")

    def embed_chunks(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        if not texts:
            return []
            
        if not self._loaded:
            self.load_model()
            
        if not self._model:
            raise EmbeddingServiceFailure("Model is not initialized.")
            
        try:
            # Generate embeddings and normalize to L2 norm = 1
            # BGE model benefits from normalization, and we want pgvector inner product
            embeddings = self._model.encode(
                texts, 
                batch_size=batch_size, 
                normalize_embeddings=True, 
                show_progress_bar=False
            )
            
            # SentenceTransformers returns a numpy array or tensor. Convert to standard python float lists.
            if isinstance(embeddings, np.ndarray):
                return embeddings.tolist()
            else:
                return [e.tolist() for e in embeddings]
        except Exception as e:
            logger.error(f"Failed to generate embeddings: {e}")
            raise EmbeddingServiceFailure(f"Failed to generate embeddings: {str(e)}")

# Singleton instance for FastAPI lifespan injection
embedding_service = LocalEmbeddingService()
