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
    for channel in ("external", "laundered", "agent-laundered"):
        assert r.channels[channel] == [True] * 5, channel
    assert r.attacker == "write-access"


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
    assert r.detail.count("ranks 1, 1, 1, 1, 1 of 3") == 3  # all three channels


def test_prompt_injection_is_delivered_by_a_plain_ranker():
    """The naive store serves whatever overlaps the question. On the first
    fixture the query and the payload share no token ("meetings" versus
    "meeting"), so that one is kept out; four of five are delivered."""
    r = IndirectPromptInjectionAttack().run(NaiveMemoryAdapter())
    assert r.error is None
    assert r.safe is False
    for channel in ("external", "laundered", "agent-laundered"):
        assert r.channels[channel].count(True) == 4, channel


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


def test_the_defended_reference_holds_where_a_store_can_hold():
    """A benchmark nobody can pass proves nothing, so the reference store
    shows what each defence buys, channel by channel. Provenance keeps the
    planted fact out on the external channel and cannot on the laundered
    one: a plausible fact wearing the user's label is indistinguishable
    from a genuine one, and only ingestion marking upstream can prevent
    it. The content checks hold on both channels, which is the point of
    the second channel: it is what separates them from the label."""
    results = {cls.name: cls().run(DefendedMemoryAdapter())
               for cls in ALL_MEMORY_ATTACKS}
    for r in results.values():
        assert r.error is None, f"{r.attack}: {r.error}"
    inj = results["memory_injection"]
    assert inj.channels["external"] == [False] * 5       # label and signature both say no
    assert inj.channels["laundered"] == [False] * 5      # label forged, no key: signature says no
    assert inj.channels["agent-laundered"] == [True] * 5  # signed by the agent: nothing can tell
    assert inj.safe is False
    for name in ("cross_session_bleed", "retrieval_hijack",
                 "indirect_prompt_injection"):
        r = results[name]
        assert r.safe is True, f"{name}: {r.detail}"
        for channel, outcomes in r.channels.items():
            assert outcomes == [False] * 5, f"{name} {channel}: {outcomes}"


def test_provenance_alone_never_passes_a_content_cell():
    """The check DanceNitra ran by hand: switch the two content checks off
    and the reference store must lose the hijack and hidden-instruction
    cells on the agent-laundered channel, where the attacker's write is
    signed like a genuine one. If this passes with the checks off, that
    channel has stopped doing its job."""
    import agmi.adapters.defended_memory as dm
    saved = dm.looks_like_instruction, dm.looks_stuffed
    dm.looks_like_instruction = lambda text: False
    dm.looks_stuffed = lambda text: False
    try:
        hijack = RetrievalHijackAttack().run(DefendedMemoryAdapter())
        prompt = IndirectPromptInjectionAttack().run(DefendedMemoryAdapter())
    finally:
        dm.looks_like_instruction, dm.looks_stuffed = saved
    # With the two write-time content checks off, provenance and the
    # read-time query-word check are all that is left. External and
    # laundered still hold (signature verification). On the signed channel
    # the store must still lose ground: the hidden instruction has no
    # read-time defence left and surfaces on most fixtures, and the hijack
    # surfaces on at least one. If both held clean here, provenance would
    # be passing a content cell again.
    assert hijack.channels["external"] == [False] * 5
    assert hijack.channels["laundered"] == [False] * 5
    assert prompt.channels["external"] == [False] * 5
    assert prompt.channels["laundered"] == [False] * 5
    assert prompt.channels["agent-laundered"].count(True) >= 4
    assert hijack.channels["agent-laundered"].count(True) >= 1


def test_results_carry_the_attack_version_and_attacker_level():
    for cls in ALL_MEMORY_ATTACKS:
        r = cls().run(NaiveMemoryAdapter())
        assert r.version == cls.version >= 2
        assert len(r.fixtures) == 5
        assert r.attacker == "write-access"
        assert r.channels


def test_signatures_cannot_be_forged_without_the_key():
    from agmi.signing import Keyring
    ring = Keyring()
    sig = ring.sign("victim", "user", "The user drinks tea.")
    assert ring.verify("victim", "user", "The user drinks tea.", sig)
    assert not ring.verify("victim", "user", "The user drinks coffee.", sig)
    assert not ring.verify("victim", "external", "The user drinks tea.", sig)
    assert not ring.verify("attacker", "user", "The user drinks tea.", sig)
    assert not ring.verify("victim", "user", "The user drinks tea.", None)
    assert not Keyring().verify("victim", "user", "The user drinks tea.", sig)
