"""
Embedding Service for AI Matching

Implements text embedding generation using OpenAI ada-002 with local fallback.
Includes caching layer to reduce API calls and improve performance.
"""
import hashlib
import logging
from dataclasses import dataclass
from typing import List, Optional

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


@dataclass
class EmbeddingResult:
    """Result of embedding generation."""
    success: bool
    vector: Optional[List[float]] = None
    model: str = ''
    error: str = ''
    dimension: int = 0
    cached: bool = False

    @property
    def embedding(self) -> Optional[List[float]]:
        """Alias for vector for convenience."""
        return self.vector


class EmbeddingService:
    """
    Service for generating text embeddings using OpenAI ada-002.

    Falls back to sentence-transformers if OpenAI is unavailable.
    Implements caching to reduce API calls and costs.

    Usage:
        service = EmbeddingService()
        result = service.execute("Software engineer with Python experience")
        if result.success:
            print(f"Embedding dimension: {result.dimension}")
            # Use result.vector for similarity calculations
    """

    CACHE_PREFIX = 'ai_embedding:v2:'

    def __init__(self):
        self.openai_api_key = getattr(settings, 'OPENAI_API_KEY', '')
        self.openai_available = bool(self.openai_api_key)
        self.cache_ttl = getattr(settings, 'AI_MATCHING_CACHE_TTL', 86400 * 7)
        self._local_model = None
        self._openai_client = None

    def execute(self, text: str, use_cache: bool = True) -> EmbeddingResult:
        """
        Generate embedding for text.

        Args:
            text: Text to embed (will be truncated if too long)
            use_cache: Whether to use cached embeddings

        Returns:
            EmbeddingResult with vector or error
        """
        if not text or not text.strip():
            return EmbeddingResult(
                success=False,
                error='Empty text provided'
            )

        # Normalize text
        text = text.strip()[:8000]  # Limit text length

        # Check cache first
        if use_cache:
            cached = self._get_cached(text)
            if cached:
                cached.cached = True
                return cached

        # Try OpenAI first
        if self.openai_available:
            result = self._generate_openai(text)
            if result.success:
                if use_cache:
                    self._cache_result(text, result)
                return result

        # Fallback to local model
        result = self._generate_local(text)
        if result.success and use_cache:
            self._cache_result(text, result)

        return result

    def execute_batch(
        self,
        texts: List[str],
        use_cache: bool = True
    ) -> List[EmbeddingResult]:
        """
        Generate embeddings for multiple texts.

        Args:
            texts: List of texts to embed
            use_cache: Whether to use cached embeddings

        Returns:
            List of EmbeddingResult objects
        """
        results = []
        uncached_texts = []
        uncached_indices = []

        # Check cache for each text
        for i, text in enumerate(texts):
            if use_cache:
                cached = self._get_cached(text)
                if cached:
                    cached.cached = True
                    results.append((i, cached))
                    continue
            uncached_texts.append(text)
            uncached_indices.append(i)
            results.append((i, None))

        # Generate embeddings for uncached texts
        if uncached_texts:
            if self.openai_available:
                batch_results = self._generate_openai_batch(uncached_texts)
            else:
                batch_results = [self._generate_local(t) for t in uncached_texts]

            # Cache and update results
            for idx, (text, result) in enumerate(zip(uncached_texts, batch_results)):
                original_idx = uncached_indices[idx]
                if result.success and use_cache:
                    self._cache_result(text, result)
                # Update the results list
                for j, (stored_idx, stored_result) in enumerate(results):
                    if stored_idx == original_idx and stored_result is None:
                        results[j] = (original_idx, result)
                        break

        # Sort by original index and return just results
        results.sort(key=lambda x: x[0])
        return [r[1] for r in results]

    def _generate_openai(self, text: str) -> EmbeddingResult:
        """Generate embedding using OpenAI API."""
        try:
            import openai

            if self._openai_client is None:
                self._openai_client = openai.OpenAI(api_key=self.openai_api_key)

            model = getattr(
                settings,
                'OPENAI_EMBEDDING_MODEL',
                'text-embedding-ada-002'
            )

            response = self._openai_client.embeddings.create(
                model=model,
                input=text[:8191],  # OpenAI token limit
            )

            vector = response.data[0].embedding

            # Record success for monitoring
            self._record_api_call('openai_embedding', success=True)

            return EmbeddingResult(
                success=True,
                vector=vector,
                model=model,
                dimension=len(vector)
            )

        except ImportError:
            logger.warning("OpenAI package not installed")
            return EmbeddingResult(
                success=False,
                error='OpenAI package not installed'
            )
        except Exception as e:
            logger.warning(f"OpenAI embedding failed: {e}")
            self._record_api_call('openai_embedding', success=False, error=str(e))
            return EmbeddingResult(
                success=False,
                error=str(e)
            )

    def _generate_openai_batch(self, texts: List[str]) -> List[EmbeddingResult]:
        """Generate embeddings for multiple texts using OpenAI batch API."""
        try:
            import openai

            if self._openai_client is None:
                self._openai_client = openai.OpenAI(api_key=self.openai_api_key)

            model = getattr(
                settings,
                'OPENAI_EMBEDDING_MODEL',
                'text-embedding-ada-002'
            )

            # Truncate texts
            truncated_texts = [t[:8191] for t in texts]

            response = self._openai_client.embeddings.create(
                model=model,
                input=truncated_texts,
            )

            results = []
            for data in response.data:
                results.append(EmbeddingResult(
                    success=True,
                    vector=data.embedding,
                    model=model,
                    dimension=len(data.embedding)
                ))

            self._record_api_call('openai_embedding_batch', success=True)
            return results

        except Exception as e:
            logger.warning(f"OpenAI batch embedding failed: {e}")
            # Fall back to individual local embeddings
            return [self._generate_local(t) for t in texts]

    def _generate_local(self, text: str) -> EmbeddingResult:
        """Generate embedding using local sentence-transformers model."""
        try:
            if self._local_model is None:
                from sentence_transformers import SentenceTransformer
                model_name = getattr(
                    settings,
                    'AI_MATCHING_FALLBACK_MODEL',
                    'all-MiniLM-L6-v2'
                )
                logger.info(f"Loading local embedding model: {model_name}")
                self._local_model = SentenceTransformer(model_name)

            # Generate embedding
            vector = self._local_model.encode(text).tolist()

            return EmbeddingResult(
                success=True,
                vector=vector,
                model='local:' + getattr(
                    settings,
                    'AI_MATCHING_FALLBACK_MODEL',
                    'all-MiniLM-L6-v2'
                ),
                dimension=len(vector)
            )

        except ImportError:
            logger.error("sentence-transformers package not installed")
            return EmbeddingResult(
                success=False,
                error='sentence-transformers package not installed. '
                      'Install with: pip install sentence-transformers'
            )
        except Exception as e:
            logger.error(f"Local embedding failed: {e}")
            return EmbeddingResult(
                success=False,
                error=str(e)
            )

    def _cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        text_hash = hashlib.sha256(text.encode()).hexdigest()[:32]
        return f"{self.CACHE_PREFIX}{text_hash}"

    def _get_cached(self, text: str) -> Optional[EmbeddingResult]:
        """Get cached embedding result."""
        try:
            data = cache.get(self._cache_key(text))
            if data:
                return EmbeddingResult(**data)
        except Exception as e:
            logger.debug(f"Cache read failed: {e}")
        return None

    def _cache_result(self, text: str, result: EmbeddingResult):
        """Cache embedding result."""
        try:
            cache.set(
                self._cache_key(text),
                {
                    'success': result.success,
                    'vector': result.vector,
                    'model': result.model,
                    'dimension': result.dimension,
                    'error': '',
                },
                self.cache_ttl
            )
        except Exception as e:
            logger.warning(f"Failed to cache embedding: {e}")

    def _record_api_call(
        self,
        service_name: str,
        success: bool,
        error: str = ''
    ):
        """Record API call for monitoring."""
        try:
            from ai_matching.models import AIServiceStatus

            status, _ = AIServiceStatus.objects.get_or_create(
                service_name=service_name,
                defaults={'is_available': True}
            )

            if success:
                status.record_success()
            else:
                status.record_failure(error)

        except Exception:
            # Don't fail if monitoring fails
            pass

    @staticmethod
    def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        """
        Calculate cosine similarity between two vectors.

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            Cosine similarity score between -1 and 1
        """
        import math

        if not vec1 or not vec2:
            return 0.0

        if len(vec1) != len(vec2):
            logger.warning(
                f"Vector dimension mismatch: {len(vec1)} vs {len(vec2)}"
            )
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = math.sqrt(sum(a * a for a in vec1))
        magnitude2 = math.sqrt(sum(b * b for b in vec2))

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    @staticmethod
    def normalize_similarity(score: float) -> float:
        """
        Normalize cosine similarity from [-1, 1] to [0, 1].

        Args:
            score: Cosine similarity score

        Returns:
            Normalized score between 0 and 1
        """
        return (score + 1) / 2


# Singleton instance for convenience
_embedding_service = None


def get_embedding_service() -> EmbeddingService:
    """Get singleton EmbeddingService instance."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service
