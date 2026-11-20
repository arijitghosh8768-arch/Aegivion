import logging
import os
import re
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


class HashingEmbeddingService:
    """Deterministic offline embedder used when no neural model is installed.

    Produces 384-dimensional, L2-normalized vectors from hashed token and
    token-bigram buckets. This is **lexical, not semantic**: it captures shared
    vocabulary only and must not be presented as semantic understanding. It
    exists so the chunk -> embed -> store -> retrieve path can run (and be
    tested) on machines without ``sentence-transformers``.

    The ``model_name`` is recorded on every chunk, so vectors produced here are
    never compared against vectors from a different embedding model.

    Attributes:
        dimension: Vector dimensionality (384).
        model_name: Identifier stored on chunks; defaults to ``aegivion-hashing-v1``.
        vector_model_id: Same as model_name; used by retrieval to prevent
            cross-model vector comparison.
        max_tokens: Maximum token count for embedding context.
    """

    def __init__(self, dimension: int = 384, model_name: str = "aegivion-hashing-v1"):
        self.dimension = dimension
        self.model_name = model_name
        self.vector_model_id = model_name
        self.max_tokens = 512
        self._token_pattern = re.compile(r"[a-z0-9]+")

    def _tokens(self, text: str) -> List[str]:
        lowered = (text or "").lower()
        unigrams = self._token_pattern.findall(lowered)
        bigrams = [f"{a}_{b}" for a, b in zip(unigrams, unigrams[1:])]
        return unigrams + bigrams

    def _embed_one(self, text: str) -> List[float]:
        import hashlib
        import math

        vector = [0.0] * self.dimension
        counts = {}
        for token in self._tokens(text):
            counts[token] = counts.get(token, 0) + 1

        for token, count in counts.items():
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            raw = int.from_bytes(digest, "big")
            index = raw % self.dimension
            sign = -1.0 if (raw >> 63) & 1 else 1.0
            # Sub-linear term frequency keeps repeated terms from dominating.
            vector[index] += sign * (1.0 + math.log(count))

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]

    def embed_chunks(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        if not texts:
            return []
        return [self._embed_one(text) for text in texts]


# Singleton instance for FastAPI lifespan injection
embedding_service = LocalEmbeddingService()

_active_embedding_service = None


def get_embedding_service():
    """Return the best available embedder for this machine.

    Prefers the real ``bge-small-en-v1.5`` model from sentence-transformers and
    falls back to the deterministic hashing embedder when it is not installed.
    The choice is cached for the process lifetime.
    """
    global _active_embedding_service
    if _active_embedding_service is not None:
        return _active_embedding_service

    # Explicit override: AEGIVION_EMBEDDING_BACKEND=hashing makes offline and
    # test runs deterministic without downloading a model.
    backend = os.getenv("AEGIVION_EMBEDDING_BACKEND", "auto").strip().lower()
    if backend == "hashing":
        _active_embedding_service = HashingEmbeddingService()
        logger.info("Using deterministic hashing embedder (AEGIVION_EMBEDDING_BACKEND=hashing).")
        return _active_embedding_service

    try:
        import sentence_transformers  # noqa: F401

        _active_embedding_service = LocalEmbeddingService()
        logger.info("Using sentence-transformers embeddings (bge-small-en-v1.5).")
    except Exception:
        logger.warning(
            "sentence-transformers is unavailable; using the deterministic "
            "hashing embedder (lexical only, not semantic)."
        )
        _active_embedding_service = HashingEmbeddingService()

    return _active_embedding_service