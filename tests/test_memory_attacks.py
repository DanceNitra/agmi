# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Tests for the four memory-specific attacks against the naive reference store.

These pin the honest baseline: a store with no provenance is always
injectable; user-scoping decides the bleed result; the naive lexical
retriever is too simple to be hijacked or to deliver markers (a weak 'safe'
that only becomes meaningful against real vector tools).
"""

from agmi.adapters.naive_memory import NaiveMemoryAdapter
from agmi.attacks.memory_specific import (
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
