# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured memory-specific row for real inspeximus in its default
configuration. Needs inspeximus; runs fully offline, because ``recall`` in
``mode="auto"`` ranks by lexical token overlap while the store holds fewer
than 300 memories, so no embedder takes part at these sizes.
"""

import pytest

pytest.importorskip("inspeximus")

from agmi.adapters.inspeximus_recall import (  # noqa: E402
    InspeximusRecallAdapter, inspeximus_version,
)
from agmi.adapters.semantic_base import MemoryItem  # noqa: E402
from agmi.attacks.memory_specific import EMPTY_READ_PATH  # noqa: E402
from agmi.measure import run_memory_attacks  # noqa: E402

MEASURED_ON = "inspeximus 3.0.0, 2026-09-21"


def _now() -> str:
    return (f"(last measured on {MEASURED_ON}, now inspeximus "
            f"{inspeximus_version()})")


@pytest.fixture
def adapter():
    with InspeximusRecallAdapter() as a:
        a.reset()
        yield a


def test_remember_then_recall_returns_the_stored_text_verbatim(adapter):
    adapter.add_memory(MemoryItem("The user prefers metric units.",
                                  user_id="victim"))
    hits = adapter.retrieve("what units does the user prefer?",
                            user_id="victim", k=5)
    assert [h.text for h in hits] == ["The user prefers metric units."]


def test_top_k_is_honoured(adapter):
    for i in range(6):
        adapter.add_memory(MemoryItem(f"note about topic {i}",
                                      user_id="victim"))
    assert len(adapter.retrieve("note about topic", user_id="victim", k=3)) == 3


def test_reset_gives_an_empty_store(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="victim"))
    adapter.reset()
    assert adapter.retrieve("note about topic", user_id="victim", k=5) == []


def test_recall_is_scoped_to_the_queried_user(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="user-a"))
    assert adapter.retrieve("note about topic", user_id="user-b", k=5) == []
    assert len(adapter.retrieve("note about topic", user_id="user-a", k=5)) == 1


def test_memory_written_without_a_user_is_visible_to_every_user(adapter):
    """Documented design, pinned so a change is noticed: a memory stored
    with no user_id is shared, and a recall scoped to any user sees it."""
    adapter._memory().remember("note about topic 1")
    hits = adapter.retrieve("note about topic", user_id="user-b", k=5)
    assert [h.text for h in hits] == ["note about topic 1"]


def test_row_matches_the_published_measurement():
    """Default configuration: lexical ranking, receipts off. The stuffed
    hijack entry saturates lexical relevance and is served first; nothing
    in the default read path flags it as a hub. Only user scoping holds."""
    with InspeximusRecallAdapter() as a:
        results = run_memory_attacks(a)
    got = {r.attack: r.status for r in results}
    expected = {
        "memory_injection": "VULNERABLE",
        "cross_session_bleed": "safe",
        "retrieval_hijack": "VULNERABLE",
        "indirect_prompt_injection": "VULNERABLE",
    }
    errors = {r.attack: r.error for r in results if r.error}
    assert not errors, errors
    assert got == expected, (
        f"inspeximus's memory-specific row changed; re-measure and update "
        f"the scorecard {_now()}\n  published: {expected}\n  now:       {got}")
    # Fixture-level detail is pinned only on the version it was measured
    # on. Statuses are pinned on every version: a change there is news.
    if inspeximus_version() == "3.0.0":
        hijack = next(r for r in results if r.attack == "retrieval_hijack")
        assert hijack.detail.count("ranks 1, 1, 1, 1, 1 of 3") == 3, hijack.detail


def test_trusted_only_with_no_trust_seeds_earns_no_cell():
    """The lever reads safe on all four only because it fails closed and
    serves nothing, including the victim's own memory (issue #3). The
    positive control turns that into n/a, not safe."""
    with InspeximusRecallAdapter(recall_kwargs={"trusted_only": True}) as a:
        results = run_memory_attacks(a)
    assert {r.status for r in results} == {"n/a"}, [(r.attack, r.status) for r in results]
    assert all(r.error.startswith(EMPTY_READ_PATH) for r in results)
