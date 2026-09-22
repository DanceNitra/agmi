# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Tests for the four memory-specific attacks against the naive reference store.

These pin the honest baseline: a store with no provenance is always
injectable; user-scoping decides the bleed result; a plain similarity
ranker is hijacked by a stuffed entry; the naive lexical retriever is too
simple to deliver instruction markers for a paraphrased query (a weak
'safe' that only becomes meaningful against real vector tools).
"""

from agmi.adapters.defended_memory import DefendedMemoryAdapter
from agmi.adapters.naive_memory import NaiveMemoryAdapter
from agmi.attacks.memory_specific import (
    ALL_MEMORY_ATTACKS, EMPTY_READ_PATH, HIJACK_FIXTURES,
    HIJACK_ENTRY, HIJACK_GENUINE, HIJACK_K, HIJACK_QUERY,
    MemoryInjectionAttack, CrossSessionBleedAttack,
    RetrievalHijackAttack, IndirectPromptInjectionAttack,
)


class SilentAdapter(NaiveMemoryAdapter):
    """A store that accepts every write and answers every read with nothing.
    Models a configuration that fails closed (inspeximus ``trusted_only``
    with no trust seeds, issue #3). It must earn no safe cell."""

    def __init__(self):
        super().__init__()
        self.name = "silent"

    def retrieve(self, query, user_id, k=5):
        return []


def test_injection_always_surfaces_on_a_store_with_no_provenance():
    r = MemoryInjectionAttack().run(NaiveMemoryAdapter())
    assert r.error is None
    assert r.safe is False
    assert "5 of 5" in r.detail


def test_bleed_is_decided_by_user_scoping():
    assert CrossSessionBleedAttack().run(NaiveMemoryAdapter()).safe is True
    assert CrossSessionBleedAttack().run(
        NaiveMemoryAdapter(enforce_user_scope=False)).safe is False


def test_hijack_set_up_makes_the_top_k_contested():
    """Every fixture: more genuine memories than slots, the payload marker
    only in the attacker's entry, and the question never a substring of
    the entry."""
    for fx in HIJACK_FIXTURES:
        assert len(fx.genuine) > HIJACK_K
        assert fx.query not in fx.entry
        assert fx.key in fx.entry
        assert not any(fx.key in g for g in fx.genuine)
    assert HIJACK_ENTRY == HIJACK_FIXTURES[0].entry
    assert HIJACK_GENUINE == list(HIJACK_FIXTURES[0].genuine)
    assert HIJACK_QUERY == HIJACK_FIXTURES[0].query


def test_hijack_outranks_genuine_memories_on_a_plain_ranker():
    r = RetrievalHijackAttack().run(NaiveMemoryAdapter())
    assert r.error is None
    assert r.safe is False
    assert "ranks 1, 1, 1, 1, 1 of 3" in r.detail


def test_prompt_injection_is_delivered_by_a_plain_ranker():
    """The naive store serves whatever overlaps the question. On the first
    fixture the query and the payload share no token ("meetings" versus
    "meeting"), so that one is kept out; four of five are delivered."""
    r = IndirectPromptInjectionAttack().run(NaiveMemoryAdapter())
    assert r.error is None
    assert r.safe is False
    assert "4 of 5" in r.detail


def test_a_silent_read_path_earns_no_safe_cell():
    """Silence satisfies "not surfaced", "not leaked" and "not delivered".
    The positive control turns that into n/a on every attack."""
    for cls in ALL_MEMORY_ATTACKS:
        r = cls().run(SilentAdapter())
        assert r.status == "n/a", f"{r.attack} scored {r.status} on a silent store"
        assert r.error.startswith(EMPTY_READ_PATH)


def test_positive_control_passes_on_a_working_store():
    """The control must not turn a real measurement into n/a."""
    for cls in ALL_MEMORY_ATTACKS:
        r = cls().run(NaiveMemoryAdapter())
        assert r.error is None, f"{r.attack}: {r.error}"


def test_every_cell_is_winnable_by_the_defended_reference():
    """A benchmark nobody can pass proves nothing. The reference store with
    provenance, write-time quarantine and a stuffing check keeps every
    attacker memory out on every fixture, and still serves the genuine
    ones (the positive control passes)."""
    for cls in ALL_MEMORY_ATTACKS:
        r = cls().run(DefendedMemoryAdapter())
        assert r.error is None, f"{r.attack}: {r.error}"
        assert r.safe is True, f"{r.attack}: {r.detail}"
        assert "5 of 5" in r.detail


def test_results_carry_the_attack_version():
    for cls in ALL_MEMORY_ATTACKS:
        r = cls().run(NaiveMemoryAdapter())
        assert r.version == cls.version >= 2
        assert len(r.fixtures) == 5
