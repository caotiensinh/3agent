from __future__ import annotations

import gc
import threading
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

from .model_artifacts import RuntimeModelResolver
from .model_residency import ModelResidencyManager


QWEN3_EMBEDDING_MODEL_ID = "qwen3-embedding-0.6b"
QWEN3_EMBEDDING_MIN_DIM = 32
QWEN3_EMBEDDING_MAX_DIM = 1024


class EmbeddingRuntimeError(RuntimeError):
    """Raised when the local embedding runtime cannot safely serve a request."""


class LocalModelResolver(Protocol):
    def resolve(self, model_id: str) -> Path: ...


class EmbeddingModel(Protocol):
    def encode_query(self, inputs: Sequence[str], **kwargs: Any) -> Any: ...

    def encode_document(self, inputs: Sequence[str], **kwargs: Any) -> Any: ...


EmbeddingLoader = Callable[[Path], EmbeddingModel]


def _load_sentence_transformer(local_path: Path) -> EmbeddingModel:
    """Load a previously provisioned model from a verified local directory only."""

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise EmbeddingRuntimeError(
            "local embedding runtime requires the optional embedding-runtime dependency"
        ) from exc

    # The path has already passed RuntimeModelResolver integrity validation.
    # local_files_only prevents a cache miss from becoming network authority and
    # trust_remote_code=False prevents repository-selected Python execution.
    return SentenceTransformer(
        str(local_path),
        local_files_only=True,
        trust_remote_code=False,
    )


class LocalSentenceTransformerBackend:
    """In-process residency backend for integrity-verified local embedding models.

    The backend owns loaded Python model objects only. Artifact identity and
    integrity remain the responsibility of RuntimeModelResolver; acquisition is
    intentionally absent from this module.
    """

    scope = "local-sentence-transformer"

    def __init__(
        self,
        resolver: LocalModelResolver,
        *,
        loader: EmbeddingLoader | None = None,
    ) -> None:
        self.resolver = resolver
        self._loader = loader or _load_sentence_transformer
        self._models: dict[str, EmbeddingModel] = {}
        self._paths: dict[str, Path] = {}
        self._lock = threading.RLock()

    def resident_models(self) -> set[str]:
        with self._lock:
            return set(self._models)

    def get_or_load(self, model_id: str) -> EmbeddingModel:
        model_id = str(model_id).strip()
        if not model_id:
            raise ValueError("embedding model id must not be empty")
        with self._lock:
            existing = self._models.get(model_id)
            if existing is not None:
                return existing

            # Resolver runs before the optional third-party loader. An unapproved,
            # missing, receipt-mismatched, or tampered model therefore fails closed
            # before Sentence Transformers can inspect any path.
            verified_path = self.resolver.resolve(model_id).resolve()
            model = self._loader(verified_path)
            self._models[model_id] = model
            self._paths[model_id] = verified_path
            return model

    def loaded_path(self, model_id: str) -> Path | None:
        with self._lock:
            return self._paths.get(str(model_id).strip())

    def unload(self, model_id: str) -> bool:
        model_id = str(model_id).strip()
        if not model_id:
            return False
        with self._lock:
            model = self._models.pop(model_id, None)
            self._paths.pop(model_id, None)
        if model is None:
            return False

        # Moving to CPU first gives CUDA allocators an opportunity to release VRAM.
        # Eviction is an optimization, so cleanup failures must not resurrect a
        # model that the residency manager has already declared inactive.
        try:
            move = getattr(model, "to", None)
            if callable(move):
                move("cpu")
        except Exception:
            pass
        del model
        gc.collect()
        try:
            import torch

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except (ImportError, RuntimeError):
            pass
        return True


class LocalEmbeddingAdapter:
    """Local-only query/document embedding with shared on-demand residency.

    This adapter does not modify WorkSpace deterministic retrieval. It is a new
    capability that can be wired into a semantic retrieval lane only after model
    approval, provisioning, evaluation, and route-policy acceptance.
    """

    def __init__(
        self,
        resolver: RuntimeModelResolver | LocalModelResolver,
        *,
        model_id: str = QWEN3_EMBEDDING_MODEL_ID,
        dimensions: int = QWEN3_EMBEDDING_MAX_DIM,
        batch_size: int = 16,
        backend: LocalSentenceTransformerBackend | None = None,
        residency: ModelResidencyManager | None = None,
    ) -> None:
        model_id = str(model_id).strip()
        if not model_id:
            raise ValueError("embedding model id must not be empty")
        dimensions = int(dimensions)
        if not QWEN3_EMBEDDING_MIN_DIM <= dimensions <= QWEN3_EMBEDDING_MAX_DIM:
            raise ValueError(
                f"embedding dimensions must be between {QWEN3_EMBEDDING_MIN_DIM} "
                f"and {QWEN3_EMBEDDING_MAX_DIM}"
            )
        batch_size = int(batch_size)
        if batch_size <= 0:
            raise ValueError("embedding batch_size must be > 0")

        self.model_id = model_id
        self.dimensions = dimensions
        self.batch_size = batch_size
        self.backend = backend or LocalSentenceTransformerBackend(resolver)
        self.residency = residency or ModelResidencyManager(self.backend)
        if self.residency.backend is not self.backend:
            raise ValueError("embedding residency manager must manage the same backend")

    @staticmethod
    def _validate_inputs(inputs: Sequence[str]) -> tuple[str, ...]:
        normalized = tuple(str(item).strip() for item in inputs)
        if not normalized:
            raise ValueError("embedding request requires at least one input")
        if any(not item for item in normalized):
            raise ValueError("embedding inputs must not contain empty text")
        return normalized

    def _encode(self, inputs: Sequence[str], *, query: bool) -> Any:
        texts = self._validate_inputs(inputs)
        with self.residency.lease(self.model_id):
            model = self.backend.get_or_load(self.model_id)
            method = model.encode_query if query else model.encode_document
            return method(
                list(texts),
                batch_size=self.batch_size,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,
                truncate_dim=self.dimensions,
            )

    def encode_queries(self, inputs: Sequence[str]) -> Any:
        """Encode retrieval queries using the model's approved query prompt."""

        return self._encode(inputs, query=True)

    def encode_documents(self, inputs: Sequence[str]) -> Any:
        """Encode documents/passages without injecting a query prompt."""

        return self._encode(inputs, query=False)

    def evict_idle(self) -> tuple[str, ...]:
        return self.residency.evict_idle()

    def snapshot(self) -> dict[str, object]:
        payload = self.residency.snapshot()
        payload.update(
            {
                "embedding_model_id": self.model_id,
                "embedding_dimensions": self.dimensions,
                "embedding_batch_size": self.batch_size,
                "runtime_download": False,
            }
        )
        return payload
