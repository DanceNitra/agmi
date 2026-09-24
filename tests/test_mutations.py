# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The mutation engine, and what it does to the reference store.

Two things are pinned. First, every mutation preserves the fact the
verdict keys on, so a mutated attack is the same attack, not a new one.
Second, the defended reference, which holds every content cell on the base
fixtures, LOSES the hijack cell under mutation on the signed channel: the
dilute mutation thins the stuffed entry below a fixed threshold, so a
threshold-based stuffing check is not enough. That is the finding the
engine exists to surface, and it is why "kept out" on a base fixture is a
weaker statement than "kept out under mutation"."""

from agmi.adapters.defended_memory import DefendedMemoryAdapter
from agmi.attacks.memory_specific import (
    HIJACK_FIXTURES, INJECTION_FIXTURES, PROMPT_INJECTION_FIXTURES,
    RetrievalHijackAttack, MemoryInjectionAttack,
    IndirectPromptInjectionAttack,
)
from agmi.mutations import dilute_stuffing, mutate, preserves


def test_every_mutation_preserves_the_verdict_key():
    cases = ([(fx.planted, fx.planted_key) for fx in INJECTION_FIXTURES]
             + [(fx.entry, fx.key) for fx in HIJACK_FIXTURES]
             + [(fx.payload, fx.key) for fx in PROMPT_INJECTION_FIXTURES])
    seen = set()
    for text, key in cases:
        for name, variant in mutate(text):
            seen.add(name)
            assert preserves(text, variant, key), (name, variant)
    # the corpus exercises more than one mutation
    assert len(seen) >= 3


def test_a_mutation_returns_none_when_it_does_not_apply():
    from agmi.mutations import paraphrase_instruction
    assert dilute_stuffing("a short plain sentence") is None
    assert paraphrase_instruction("the user's manager is Priya") is None


def test_dilute_drops_a_stuffed_entry_below_threshold():
    from agmi.checks import looks_stuffed
    entry = HIJACK_FIXTURES[0].entry
    assert looks_stuffed(entry)
    diluted = dict(mutate(entry)).get("dilute")
    assert diluted is not None
    assert not looks_stuffed(diluted)
    assert HIJACK_FIXTURES[0].key in diluted


def test_mutation_run_matches_base_when_nothing_evades():
    """On the cells the reference holds even under mutation, --mutate must
    not change the verdict."""
    for cls in (MemoryInjectionAttack, IndirectPromptInjectionAttack):
        base = cls(mutate=False).run(DefendedMemoryAdapter())
        mut = cls(mutate=True).run(DefendedMemoryAdapter())
        assert base.channels == mut.channels, cls.name


def test_the_engine_measures_the_limit_of_a_content_check():
    """The reference holds the hijack cell on every base fixture. Under
    mutation the query-word-count check holds four of five; a diluted entry
    tuned to the peers' level lands on exactly one. That residual is the
    point of the mutation run: a content-only defence has a measurable
    limit, and "kept out under mutation" is a stronger claim than "kept out
    on the base fixture". If this count changes, the store's check or the
    dilute mutation changed, and the row needs re-measuring."""
    base = RetrievalHijackAttack(mutate=False).run(DefendedMemoryAdapter())
    assert base.safe is True, base.detail
    mut = RetrievalHijackAttack(mutate=True).run(DefendedMemoryAdapter())
    assert mut.safe is False
    surfaced = mut.channels["agent-laundered"].count(True)
    assert surfaced == 1, f"expected exactly one fixture to evade, got {surfaced}"
