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

from agmi.adapters.naive_memory import NaiveMemoryAdapter
from agmi.attacks.memory_specific import (
    HIJACK_ENTRY, HIJACK_GENUINE, HIJACK_K, HIJACK_QUERY,
    MemoryInjectionAttack, CrossSessionBleedAttack,
    RetrievalHijackAttack, IndirectPromptInjectionAttack,
)


def test_injection_always_hits_unprotected_store():
    r = MemoryInjectionAttack().run(NaiveMemoryAdapter())
    assert r.safe is False
    assert r.error is None


def test_bleed_blocked_when_scoped():
    r = CrossSessionBleedAttack().run(
        NaiveMemoryAdapter(enforce_user_scope=True))
    assert r.safe is True


def test_bleed_leaks_when_unscoped():
    r = CrossSessionBleedAttack().run(
        NaiveMemoryAdapter(enforce_user_scope=False))
    assert r.safe is False
    assert "leaked" in r.detail


def test_memory_attacks_never_error_on_naive():
    for scope in (True, False):
        a = NaiveMemoryAdapter(enforce_user_scope=scope)
        for cls in (MemoryInjectionAttack, CrossSessionBleedAttack,
                    RetrievalHijackAttack, IndirectPromptInjectionAttack):
            assert cls().run(a).error is None


def test_hijack_set_up_makes_the_top_k_contested():
    """The attack only means something if a slot taken by the attacker is a
    slot taken from a genuine memory, and if the attacker did not simply
    store the question."""
    assert len(HIJACK_GENUINE) > HIJACK_K
    assert HIJACK_QUERY not in HIJACK_ENTRY
    assert "PAYLOAD" in HIJACK_ENTRY
    assert not any("PAYLOAD" in g for g in HIJACK_GENUINE)


def test_hijack_outranks_genuine_memories_on_a_plain_ranker():
    r = RetrievalHijackAttack().run(NaiveMemoryAdapter())
    assert r.error is None
    assert r.safe is False
    assert "rank 1 of 3" in r.detail
