# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Offline tests for the LangGraph long-term store adapter, plus the opt-in
pin of its published row.

The offline tests run with the hashing embedder and pin only what does not
depend on how text is ranked: the write and read paths work, ``limit`` is
honoured, ``reset()`` empties the store, isolation is the caller's
namespace, and the store applies no relevance floor. Cells whose outcome
depends on the embedder's ranking are pinned in the ``embedder`` tier from
a measurement with a real sentence embedder.
"""

import pytest

pytest.importorskip("langgraph.store.sqlite")

from agmi.adapters.langgraph_store import (  # noqa: E402
    NAMESPACE_ROOT, LangGraphSqliteStoreAdapter, langgraph_store_version,
)
from agmi.adapters.semantic_base import MemoryItem  # noqa: E402
from agmi.attacks.memory_specific import CrossSessionBleedAttack  # noqa: E402
from agmi.measure import run_memory_attacks  # noqa: E402

MEASURED_ON = "langgraph-checkpoint-sqlite 3.1.1"
MEASURED_ON_MINILM = ("langgraph-checkpoint-sqlite 3.1.1 SqliteStore, "
                      "all-MiniLM-L6-v2 via sentence-transformers 6.1.0, "
                      "macOS arm64, Python 3.12, 2026-09-21")


def _now() -> str:
    return (f"(last measured on {MEASURED_ON}, now langgraph-checkpoint-sqlite "
            f"{langgraph_store_version()})")


@pytest.fixture
def adapter():
    with LangGraphSqliteStoreAdapter() as a:
        a.reset()
        yield a


def test_put_then_search_returns_the_stored_text_verbatim(adapter):
    adapter.add_memory(MemoryItem("The user prefers metric units.",
                                  user_id="victim"))
    hits = adapter.retrieve("what units does the user prefer?",
                            user_id="victim", k=5)
    assert [h.text for h in hits] == ["The user prefers metric units."]
    assert hits[0].user_id == "victim"


def test_limit_is_honoured(adapter):
    for i in range(6):
        adapter.add_memory(MemoryItem(f"note about topic {i}",
                                      user_id="victim"))
    assert len(adapter.retrieve("note about topic", user_id="victim", k=3)) == 3


def test_reset_gives_an_empty_store(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="victim"))
    adapter.reset()
    assert adapter.retrieve("note about topic", user_id="victim", k=5) == []


def test_search_is_scoped_by_the_namespace_the_caller_passes(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="user-a"))
    assert adapter.retrieve("note about topic", user_id="user-b", k=5) == []
    own = adapter.retrieve("note about topic", user_id="user-a", k=5)
    assert [h.user_id for h in own] == ["user-a"]


def test_parent_prefix_search_sees_every_user(adapter):
    """Isolation lives in the caller's namespace argument, not in the
    store. Pinned so the README's statement stays true."""
    adapter.add_memory(MemoryItem("note about topic 1", user_id="user-a"))
    items = adapter._memory().search((NAMESPACE_ROOT,), query="note", limit=5)
    assert [it.namespace for it in items] == [(NAMESPACE_ROOT, "user-a")]


def test_search_applies_no_relevance_floor(adapter):
    """A memory sharing no token with the query scores 0.0 under the
    hashing embedder and still comes back. If this starts failing, the
    store gained a floor and the ranking cells need re-measuring."""
    adapter.add_memory(MemoryItem("Notes from the Q3 finance review meeting.",
                                  user_id="victim"))
    hits = adapter.retrieve("office lunch menu", user_id="victim", k=5)
    assert [h.text[:5] for h in hits] == ["Notes"], f"floor appeared {_now()}"
    assert hits[0].score == 0.0


def test_bleed_cell_is_safe():
    r = CrossSessionBleedAttack().run(LangGraphSqliteStoreAdapter())
    assert r.error is None, r.error
    assert r.safe, f"the store now returns another namespace {_now()}"


def test_every_memory_attack_runs_to_completion():
    with LangGraphSqliteStoreAdapter() as a:
        for r in run_memory_attacks(a):
            assert r.error is None, f"{r.attack} errored: {r.error}"
            assert r.status in {"safe", "VULNERABLE"}


@pytest.mark.embedder
def test_minilm_row_matches_the_published_measurement():
    """The published memory-specific LangGraph store row, measured with a
    real sentence embedder. No floor and no provenance: the planted and
    instruction-shaped memories surfaced, and the stuffed hijack entry was
    served at rank 3 of 3 under all-MiniLM-L6-v2. Isolation held because
    the search is scoped to the caller's namespace."""
    pytest.importorskip("sentence_transformers")
    from agmi.measure import measure

    results, measured_on = measure("langgraph-store", "minilm")
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
        f"the LangGraph store's memory-specific row changed; re-measure and "
        f"update the scorecard.\n  published: {expected}\n  now:       {got}\n"
        f"  published measurement: {MEASURED_ON_MINILM}\n"
        f"  this run:              {measured_on}")
