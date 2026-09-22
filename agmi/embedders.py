# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Embedders the Mem0 adapters run with.

Mem0 turns every memory into a vector and ranks retrieval by cosine distance
in Qdrant, so the embedder plugged in decides two different things:

* For the at-rest attacks, nothing. Those attacks edit bytes on disk and ask
  whether Mem0 notices on reload. Any embedder that yields a fixed-width
  vector will do, and the deterministic hashing embedder keeps that row
  offline and byte-for-byte reproducible.
* For the memory-specific attacks, the ranking. Whether a planted or padded
  entry reaches the agent's context depends on where the embedder places it
  relative to genuine memories. Cells that depend on ranking are published
  only when measured with a real sentence embedder, never with the hashing
  stand-in, because the stand-in would measure this suite, not Mem0.

Two embedders are provided:

HashEmbedder
    Offline, deterministic, lexical. Seeds the at-rest rows and exercises
    the semantic adapter's plumbing in CI.

SentenceTransformerEmbedder
    all-MiniLM-L6-v2 through sentence-transformers. Downloads about 90 MB
    once, then runs from the local cache. Opt-in through the ``embedder``
    extra. The memory-specific Mem0 cells are measured with this one.

Both expose the two things Mem0 needs: ``embed(text, memory_action)`` and
``dims``, the vector width the Qdrant collection is created with.
"""

from __future__ import annotations

import hashlib
import importlib.util
import math
import re
from typing import Protocol


class Embedder(Protocol):
    """What ``Memory.embedding_model`` has to look like for these adapters."""

    #: Short name used in row labels, e.g. "hash", "minilm".
    name: str
    #: Vector width. The Qdrant collection is created with this size.
    dims: int

    def embed(self, text: str, memory_action: str | None = None) -> list[float]:
        """Return one vector for ``text``. Mem0 passes ``memory_action`` as
        "add", "search" or "update"; it is accepted and ignored here."""
        ...

    def describe(self) -> str:
        """One line naming the model and library version, for reports."""
        ...


HASH_DIMS = 64
_TOKEN = re.compile(r"[a-z0-9]+")


class HashEmbedder:
    """Deterministic bag-of-words embedder so Mem0 runs with no network.

    Each lower-cased alphanumeric token is hashed with SHA-256 into one of
    ``dims`` buckets and adds +1 or -1 to it, then the vector is unit
    normalised. Two texts are close only when they share tokens. This is a
    lexical stand-in, not a semantic model, and is used only where ranking
    does not matter to the measurement.
    """

    name = "hash"
    dims = HASH_DIMS

    def embed(self, text: str, memory_action: str | None = None) -> list[float]:
        v = [0.0] * self.dims
        for tok in _TOKEN.findall(text.lower()):
            h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
            v[h % self.dims] += 1.0 if (h >> 8) % 2 else -1.0
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / n for x in v]

    def describe(self) -> str:
        return f"agmi hashing embedder ({self.dims} dims, lexical, offline)"


MINILM_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
BGE_SMALL_MODEL = "BAAI/bge-small-en-v1.5"


class SentenceTransformerEmbedder:
    """A real sentence embedder: all-MiniLM-L6-v2 via sentence-transformers.

    The model is fetched from the Hugging Face hub on first use and cached
    under the user's Hugging Face cache directory after that. To force the
    cached copy and refuse any download, set ``HF_HUB_OFFLINE=1`` in the
    environment before running.

    Raises ``NotImplementedError`` when sentence-transformers is not
    installed, which the attacks score as ``n/a``, never as a pass.
    """

    name = "minilm"
    dims = 384

    def __init__(self, model_id: str = MINILM_MODEL, device: str = "cpu"):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise NotImplementedError(
                "sentence-transformers is not installed; run "
                "pip install 'agent-memory-integrity[embedder]'") from exc
        self.model_id = model_id
        self._model = SentenceTransformer(model_id, device=device)
        # sentence-transformers 6 renamed the getter; support both.
        getter = getattr(self._model, "get_embedding_dimension", None) \
            or self._model.get_sentence_embedding_dimension
        reported = getter()
        if reported:
            self.dims = int(reported)

    @staticmethod
    def available() -> bool:
        """True when the sentence-transformers package can be imported.
        Says nothing about whether the model weights are cached."""
        return importlib.util.find_spec("sentence_transformers") is not None

    def embed(self, text: str, memory_action: str | None = None) -> list[float]:
        vec = self._model.encode(
            text, normalize_embeddings=True, convert_to_numpy=True,
            show_progress_bar=False)
        return [float(x) for x in vec.tolist()]

    def describe(self) -> str:
        import sentence_transformers
        return (f"{self.model_id} ({self.dims} dims) via sentence-transformers "
                f"{sentence_transformers.__version__}")


class BgeSmallEmbedder(SentenceTransformerEmbedder):
    """A second real sentence embedder, from a different family, so a rank
    on the scorecard can be shown to hold under more than one model."""

    name = "bge-small"

    def __init__(self, device: str = "cpu"):
        super().__init__(model_id=BGE_SMALL_MODEL, device=device)


EMBEDDERS: dict[str, type] = {
    HashEmbedder.name: HashEmbedder,
    SentenceTransformerEmbedder.name: SentenceTransformerEmbedder,
    BgeSmallEmbedder.name: BgeSmallEmbedder,
}


def get_embedder(name: str) -> Embedder:
    """Build an embedder by its short name ("hash", "minilm", "bge-small")."""
    try:
        cls = EMBEDDERS[name]
    except KeyError:
        raise ValueError(
            f"unknown embedder {name!r}; choose one of "
            f"{', '.join(sorted(EMBEDDERS))}") from None
    return cls()
