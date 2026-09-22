# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for Mem0 (mem0ai), the real library, memory-specific attack surface.

Where ``mem0_at_rest`` edits Mem0's files behind its back, this adapter never
touches the store. It drives Mem0 the way an agent does, through its own
write and read paths, so the four memory-specific attacks can ask whether a
planted, padded or leaked memory reaches the agent's context.

Write path
    ``Memory.add(text, user_id=..., infer=False)``. With ``infer=False`` Mem0
    stores the text as given. The default, ``infer=True``, first runs the
    text through a hosted LLM that extracts "facts" and may rewrite or drop
    them; that needs an API key and a network, so it is not measured here.
    Storage, user scoping and ranking, which is what these attacks measure,
    are the same under both modes. The extraction step is a separate
    guarantee, and the row label carries ``infer=False`` so nobody reads one
    as the other.

Read path
    ``Memory.search(query, filters={"user_id": ...}, top_k=k)``, the call an
    agent makes to fetch context, with every other parameter left at Mem0's
    default. Results are passed to the attack exactly as Mem0 returns them:
    no client-side filtering and no floor of this suite's own. If Mem0 hands
    back another user's memory, the attack sees it. The ``user_id`` on each
    hit is the one Mem0 reports; an empty string means Mem0 returned a hit
    without saying whose it is.

    On mem0ai 2.0.20 the default read path drops any candidate whose
    semantic score is below 0.1 before ranking, then adds BM25 keyword and
    entity-link boosts only when the optional ``mem0ai[extras]`` and
    ``mem0ai[nlp]`` packages are installed, and reranks only when asked to.
    A default install is therefore semantic-only with a 0.1 floor, which is
    what ``measured_on()`` records. The floor is Mem0's, so a cell that says
    "safe" because the planted text fell under it is a true measurement of
    Mem0's read path with the named embedder, not of this suite.

Embedder
    Passed in. Mem0 ranks by cosine distance over whatever embedder it is
    given, so the hijack cell in particular measures Mem0 only when the
    embedder is a real sentence model. See ``agmi.embedders`` for which
    cells depend on ranking and which do not.

Store
    A fresh private local Qdrant store under a temporary directory for every
    ``reset()``, opened exactly as the at-rest adapter opens it, so the two
    rows describe the same product configured the same way.
"""

from __future__ import annotations

import importlib.util
import platform
import sys
import tempfile
from pathlib import Path

from agmi.adapters.mem0_common import (
    close_local_memory, mem0_version, open_local_memory,
)
from agmi.adapters.semantic_base import (
    MemoryItem, Retrieved, SemanticMemoryAdapter,
)
from agmi.embedders import Embedder, HashEmbedder, get_embedder

#: Row label as it appears on the scorecard. The runner may override it.
LABEL = "mem0-qdrant-local"


class Mem0SemanticAdapter(SemanticMemoryAdapter):
    """Real Mem0 on a private local store, for the memory-specific attacks.

    Parameters
    ----------
    embedder:
        The embedder Mem0 vectorises with. Defaults to the offline hashing
        embedder, which is enough to exercise storage and scoping but not
        ranking. Pass ``SentenceTransformerEmbedder()`` for a measurement
        that can be published for every cell.
    label:
        Scorecard row name. Defaults to ``LABEL``.
    infer:
        ``True`` runs Mem0's default mode, where its own hosted LLM extracts
        facts from each memory before storage. Needs a real
        ``OPENAI_API_KEY``; the row is a separate, opt-in measurement with
        the model and date named, and is never run with a stand-in.

    The adapter opens its store lazily on first use and on every
    ``reset()``. Call ``close()`` (or use it as a context manager) when done
    so the temporary directory is removed; the runner does this.
    """

    def __init__(self, embedder: Embedder | None = None,
                 label: str | None = None, infer: bool = False):
        self.embedder: Embedder = embedder or HashEmbedder()
        self.infer = infer
        self.name = label or LABEL
        self._dir: tempfile.TemporaryDirectory | None = None
        self._root: Path | None = None
        self._mem = None

    # --- lifecycle -----------------------------------------------------
    def reset(self) -> None:
        """Throw the store away and start from an empty one."""
        self.close()
        self._dir = tempfile.TemporaryDirectory(prefix="agmi-mem0-semantic-")
        self._root = Path(self._dir.name)
        self._mem = open_local_memory(self._root, self.embedder,
                                      live=self.infer)

    def close(self) -> None:
        """Release Mem0's handles and delete the store. Idempotent."""
        close_local_memory(self._mem)
        self._mem = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None
        self._root = None

    def _memory(self):
        if self._mem is None:
            self.reset()
        return self._mem

    def __enter__(self) -> "Mem0SemanticAdapter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - interpreter teardown
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    # --- the tool's own write and read paths ---------------------------
    def add_memory(self, item: MemoryItem) -> None:
        metadata = dict(item.metadata)
        metadata.setdefault("source", item.source)
        self._memory().add(item.text, user_id=item.user_id, infer=self.infer,
                           metadata=metadata)

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        mem = self._memory()
        # mem0ai 2.x names the result count ``top_k`` and swallows unknown
        # keywords, so ``limit=`` would be ignored and 20 returned. Older
        # releases only know ``limit`` and reject ``top_k`` with TypeError.
        try:
            res = mem.search(query, filters={"user_id": user_id}, top_k=k)
        except TypeError:
            res = mem.search(query, filters={"user_id": user_id}, limit=k)
        hits = res.get("results", []) if isinstance(res, dict) else res
        out: list[Retrieved] = []
        for hit in hits or []:
            out.append(Retrieved(
                text=str(hit.get("memory", "")),
                user_id=str(hit.get("user_id") or ""),
                score=float(hit.get("score") or 0.0),
            ))
        return out

    def supports_users(self) -> bool:
        return True

    # --- provenance for reports ----------------------------------------
    @staticmethod
    def read_path_features() -> str:
        """Which optional ranking signals this install of Mem0 has. Mem0
        enables BM25 keyword scoring when ``fastembed`` is importable and
        entity-link boosts when ``spacy`` is; neither ships by default."""
        on = []
        if importlib.util.find_spec("fastembed") is not None:
            on.append("bm25 keyword scoring")
        if importlib.util.find_spec("spacy") is not None:
            on.append("entity boosts")
        return ", ".join(on) if on else "semantic only, no keyword or entity boosts"

    def measured_on(self) -> str:
        """One line stating what this row was produced with."""
        return (f"mem0ai {mem0_version()}, infer={self.infer}, default search "
                f"({self.read_path_features()}), "
                f"{self.embedder.describe()}, "
                f"{platform.system()} {platform.machine()}, "
                f"Python {sys.version_info.major}.{sys.version_info.minor}")


# --- measurement command -----------------------------------------------

def measure(embedder_name: str = "minilm"):
    """Run the four memory-specific attacks against real Mem0 and return
    ``(results, measured_on)``. Used by the command below and by tests."""
    from agmi.attacks.memory_specific import ALL_MEMORY_ATTACKS
    with Mem0SemanticAdapter(get_embedder(embedder_name)) as adapter:
        results = [cls().run(adapter) for cls in ALL_MEMORY_ATTACKS]
        return results, adapter.measured_on()


def main(argv: list[str] | None = None) -> int:
    """Print the Mem0 memory-specific row with its provenance line.

    ``python -m agmi.adapters.mem0_semantic --embedder minilm`` is the
    measurement that goes into the scorecard; ``--embedder hash`` exercises
    the same code offline without a model.
    """
    import argparse

    from agmi.embedders import EMBEDDERS

    parser = argparse.ArgumentParser(
        prog="python -m agmi.adapters.mem0_semantic",
        description=main.__doc__.split("\n\n")[0])
    parser.add_argument("--embedder", choices=sorted(EMBEDDERS),
                        default="minilm")
    args = parser.parse_args(argv)

    try:
        results, measured_on = measure(args.embedder)
    except NotImplementedError as exc:
        print(f"cannot measure: {exc}", file=sys.stderr)
        return 2

    print(f"target      {LABEL} (infer=False, embedder={args.embedder})")
    print(f"measured on {measured_on}\n")
    for r in results:
        print(f"  {r.attack:28s} {r.status:12s} {r.detail or r.error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
