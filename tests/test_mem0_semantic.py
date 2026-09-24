# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Offline tests for the Mem0 memory-specific adapter.

These run with the hashing embedder and pin only what does not depend on
how text is ranked: the write and read paths work, ``top_k`` is honoured,
``reset()`` empties the store, user scoping holds (the bleed cell), and
Mem0's default relevance floor exists. Cells whose outcome depends on the
embedder's ranking (injection, hijack, indirect prompt injection) are pinned
separately once measured with a real sentence embedder, in the opt-in
``embedder`` tier, so the offline suite never publishes a number that
measures the hashing stand-in instead of Mem0.
"""

import pytest

pytest.importorskip("mem0")
pytest.importorskip("qdrant_client")

from agmi.adapters.mem0_common import mem0_version  # noqa: E402
from agmi.adapters.mem0_semantic import Mem0SemanticAdapter  # noqa: E402
from agmi.adapters.semantic_base import MemoryItem  # noqa: E402
from agmi.attacks.memory_specific import (  # noqa: E402
    ALL_MEMORY_ATTACKS, CrossSessionBleedAttack,
)

MEASURED_ON = "mem0ai 2.0.20"
MEASURED_ON_MINILM = ("mem0ai 2.0.20 default install, all-MiniLM-L6-v2 via "
                      "sentence-transformers 6.1.0, macOS arm64, Python 3.12, "
                      "2026-09-21")


def _now() -> str:
    return f"(last measured on {MEASURED_ON}, now mem0ai {mem0_version()})"


@pytest.fixture
def adapter():
    with Mem0SemanticAdapter() as a:
        a.reset()
        yield a


def test_add_then_retrieve_returns_the_stored_text_verbatim(adapter):
    """With infer=False Mem0 stores the bytes it was given and returns them
    unchanged, attributed to the user they were stored for."""
    adapter.add_memory(MemoryItem("The user prefers metric units.",
                                  user_id="victim"))
    hits = adapter.retrieve("what units does the user prefer?",
                            user_id="victim", k=5)
    assert [h.text for h in hits] == ["The user prefers metric units."]
    assert hits[0].user_id == "victim"
    assert hits[0].score > 0.0


def test_top_k_is_honoured(adapter):
    """Guards the top_k/limit mix-up: mem0ai 2.x ignores ``limit=`` and would
    return its default of 20. Six relevant memories, k=3, three back."""
    for i in range(6):
        adapter.add_memory(MemoryItem(f"note about topic {i}",
                                      user_id="victim"))
    hits = adapter.retrieve("note about topic", user_id="victim", k=3)
    assert len(hits) == 3


def test_reset_gives_an_empty_store(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="victim"))
    adapter.reset()
    assert adapter.retrieve("note about topic", user_id="victim", k=5) == []


def test_search_is_scoped_to_the_queried_user(adapter):
    """Mem0 filters on the user_id payload inside Qdrant. That filter, not
    the embedder, decides the bleed cell, so it is pinned offline."""
    adapter.add_memory(MemoryItem("note about topic 1", user_id="user-a"))
    assert adapter.retrieve("note about topic", user_id="user-b", k=5) == []
    own = adapter.retrieve("note about topic", user_id="user-a", k=5)
    assert [h.user_id for h in own] == ["user-a"]


def test_bleed_cell_is_safe():
    r = CrossSessionBleedAttack().run(Mem0SemanticAdapter())
    assert r.error is None, r.error
    assert r.safe, (
        f"Mem0 now leaks across users; re-measure and update the scorecard "
        f"{_now()}")


def test_read_path_drops_candidates_under_the_default_floor(adapter):
    """mem0ai 2.0.20 discards any candidate whose semantic score is below
    0.1 before ranking. A memory sharing no token with the query scores 0
    under the hashing embedder and must not come back. If this starts
    failing, Mem0 changed its default floor and every memory-specific cell
    needs re-measuring."""
    adapter.add_memory(MemoryItem("Notes from the Q3 finance review meeting.",
                                  user_id="victim"))
    hits = adapter.retrieve("office lunch menu", user_id="victim", k=5)
    assert hits == [], (
        f"Mem0's default search floor has changed {_now()}: {hits}")


def test_every_memory_attack_runs_to_completion():
    """No cell may be n/a on a working install. Verdicts are not asserted
    here because three of the four depend on ranking."""
    with Mem0SemanticAdapter() as a:
        for cls in ALL_MEMORY_ATTACKS:
            r = cls().run(a)
            assert r.error is None, f"{r.attack} errored: {r.error}"
            assert r.status in {"safe", "VULNERABLE"}


def test_measured_on_records_version_embedder_and_features():
    with Mem0SemanticAdapter() as a:
        line = a.measured_on()
    assert f"mem0ai {mem0_version()}" in line
    assert "infer=False" in line
    assert "hashing embedder" in line
    assert "default search (" in line


@pytest.mark.embedder
def test_minilm_row_matches_the_published_measurement():
    """The published memory-specific Mem0 row. Retrieval is filtered on
    user_id inside Qdrant, so the bleed cell held. Nothing records where a
    memory came from, inspects what is returned, or looks past cosine
    similarity, so the planted memory, the stuffed hijack entry (served at
    rank 2 of 3 under all-MiniLM-L6-v2) and the instruction-shaped memory
    all surfaced."""
    pytest.importorskip("sentence_transformers")
    from agmi.adapters.mem0_semantic import measure

    results, measured_on = measure("minilm")
    got = {r.attack: r.status for r in results
           if r.attack in ("memory_injection", "cross_session_bleed",
                           "retrieval_hijack", "indirect_prompt_injection")}
    expected = {
        "memory_injection": "VULNERABLE",
        "cross_session_bleed": "safe",
        "retrieval_hijack": "VULNERABLE",
        "indirect_prompt_injection": "VULNERABLE",
    }
    errors = {r.attack: r.error for r in results
              if r.error and not (r.attack == "metadata_poisoning"
                                  and "no metadata filter" in r.error)}
    assert not errors, errors
    assert got == expected, (
        f"Mem0's memory-specific row changed; re-measure and update the "
        f"scorecard.\n  published: {expected}\n  now:       {got}\n"
        f"  published measurement: {MEASURED_ON_MINILM}\n"
        f"  this run:              {measured_on}")
