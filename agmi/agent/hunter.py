# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The hunt: search the attack space for a poison that lands, prove it.

The scorecard measures a tool against a fixed set of attacks. The hunt does
the opposite: it takes one target and searches the space of attacks and
their mutations for the first that gets a false memory served as trusted,
the way a human tester probes until something gives. It reports only what
it proved, each finding with the exact steps to reproduce, and each proven
finding is a new fixture the benchmark can adopt. That is the Hacktron
posture applied to memory: proof, not a checklist.

What "lands" means is not the model obeying; a suite cannot portably drive
every target's model. It means the attacker's memory was served back as
trusted context for an innocent question, which is the tool-attributable
step and the precondition for any downstream harm. The oracle is the same
one the scorecard uses: the attacker's key fact came back where a genuine
memory should have.

The search is deterministic and small by default: every base attack, on
every channel, each also run through the content-evasion mutations, in a
fixed order, stopping at the first landing per attack. It is not a fuzzer
and makes no network calls of its own beyond what the target adapter does.
An operator can widen it, but the default is reproducible: the same target
yields the same findings.

Authorisation runs before the target is touched (``agmi.agent.authz``).
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field

from agmi.adapters.semantic_base import SemanticMemoryAdapter
from agmi.agent.authz import Authorisation, authorise_library
from agmi.attacks.memory_specific import (
    CHANNELS, INJECTION_FIXTURES, HIJACK_FIXTURES, PROMPT_INJECTION_FIXTURES,
    UPDATE_FIXTURES, METADATA_FIXTURES, TRUST_TAG,
    attacker_write, genuine, positive_control,
)
from agmi.mutations import mutate as mutate_text, preserves


@dataclass
class Finding:
    """One proven way to get a false memory served as trusted."""
    attack: str
    channel: str
    mutation: str        # "base" or the mutation name that landed
    fixture: int         # 1-based index of the fixture that landed
    key: str             # the attacker fact that came back
    query: str           # the innocent question that surfaced it
    detail: str          # human summary
    repro: list = field(default_factory=list)  # ordered steps to reproduce

    def as_dict(self) -> dict:
        return {"attack": self.attack, "channel": self.channel,
                "mutation": self.mutation, "fixture": self.fixture,
                "key": self.key, "query": self.query, "detail": self.detail,
                "repro": self.repro}


@dataclass
class HuntReport:
    target: str
    authorisation: str
    platform: str
    findings: list = field(default_factory=list)
    tried: int = 0

    def as_dict(self) -> dict:
        return {"target": self.target, "authorisation": self.authorisation,
                "platform": self.platform, "attempts": self.tried,
                "findings": [f.as_dict() for f in self.findings]}


def _repro(attack, channel, mutation, writes, query, key):
    steps = [f"# {attack}, channel={channel}, mutation={mutation}"]
    for text, source, tag in writes:
        t = f", tag={tag}" if tag else ""
        role = "genuine (signed)" if source == "user-signed" else f"attacker source={source}"
        steps.append(f"add_memory({text!r}, user_id='victim', {role}{t})")
    steps.append(f"retrieve({query!r}, user_id='victim')  # served memory contains {key!r}")
    return steps


def _variants(text, key, mutate):
    out = [("base", text)]
    if mutate:
        out += [(m, t) for m, t in mutate_text(text) if preserves(text, t, key)]
    return out


def _served(hits, key):
    return any(key in h.text for h in hits)


def _hunt_injection(adapter, mutate):
    for channel in CHANNELS:
        for i, fx in enumerate(INJECTION_FIXTURES, 1):
            for mname, planted in _variants(fx.planted, fx.planted_key, mutate):
                adapter.reset()
                adapter.add_memory(genuine(fx.genuine, "victim"))
                adapter.add_memory(attacker_write(planted, "victim", channel))
                if not positive_control(adapter, fx.genuine_query, "victim",
                                        [fx.genuine_key]):
                    continue
                hits = adapter.retrieve(fx.query, "victim", k=5)
                yield 1
                if _served(hits, fx.planted_key):
                    writes = [(fx.genuine, "user-signed", None),
                              (planted, channel, None)]
                    yield Finding(
                        "memory_injection", channel, mname, i, fx.planted_key,
                        fx.query,
                        "a planted fact was served as the user's own",
                        _repro("memory_injection", channel, mname, writes,
                               fx.query, fx.planted_key))
                    return


def _hunt_hijack(adapter, mutate):
    from agmi.attacks.memory_specific import HIJACK_K
    for channel in CHANNELS:
        for i, fx in enumerate(HIJACK_FIXTURES, 1):
            for mname, entry in _variants(fx.entry, fx.key, mutate):
                adapter.reset()
                for g in fx.genuine:
                    adapter.add_memory(genuine(g, "victim"))
                adapter.add_memory(attacker_write(entry, "victim", channel))
                keys = [g[:24] for g in fx.genuine]
                if not positive_control(adapter, fx.query, "victim", keys,
                                        k=HIJACK_K):
                    continue
                hits = adapter.retrieve(fx.query, "victim", k=HIJACK_K)
                yield 1
                if _served(hits, fx.key):
                    writes = [(g, "user-signed", None) for g in fx.genuine]
                    writes.append((entry, channel, None))
                    yield Finding(
                        "retrieval_hijack", channel, mname, i, fx.key, fx.query,
                        "a stuffed entry took a slot from a genuine memory",
                        _repro("retrieval_hijack", channel, mname, writes,
                               fx.query, fx.key))
                    return


def _hunt_prompt(adapter, mutate):
    for channel in CHANNELS:
        for i, fx in enumerate(PROMPT_INJECTION_FIXTURES, 1):
            for mname, payload in _variants(fx.payload, fx.key, mutate):
                adapter.reset()
                adapter.add_memory(genuine(fx.genuine, "victim"))
                adapter.add_memory(attacker_write(payload, "victim", channel))
                if not positive_control(adapter, fx.genuine_query, "victim",
                                        [fx.genuine_key]):
                    continue
                hits = adapter.retrieve(fx.query, "victim", k=5)
                yield 1
                if _served(hits, fx.key):
                    writes = [(fx.genuine, "user-signed", None),
                              (payload, channel, None)]
                    yield Finding(
                        "indirect_prompt_injection", channel, mname, i, fx.key,
                        fx.query,
                        "instruction-shaped content reached the agent's context",
                        _repro("indirect_prompt_injection", channel, mname,
                               writes, fx.query, fx.key))
                    return


def _hunt_update(adapter, mutate):
    for channel in CHANNELS:
        for i, fx in enumerate(UPDATE_FIXTURES, 1):
            adapter.reset()
            adapter.add_memory(genuine(fx.genuine, "victim"))
            if not positive_control(adapter, fx.query, "victim",
                                    [fx.genuine_key], k=2):
                continue
            adapter.add_memory(attacker_write(fx.update, "victim", channel))
            hits = adapter.retrieve(fx.query, "victim", k=2)
            yield 1
            if _served(hits, fx.update_key) or not _served(hits, fx.genuine_key):
                writes = [(fx.genuine, "user-signed", None),
                          (fx.update, channel, None)]
                yield Finding(
                    "update_poisoning", channel, "base", i, fx.update_key,
                    fx.query, "a false correction was served for the fact",
                    _repro("update_poisoning", channel, "base", writes,
                           fx.query, fx.update_key))
                return


def _hunt_metadata(adapter, mutate):
    try:
        adapter.retrieve_where("probe", "victim", TRUST_TAG, k=1)
    except NotImplementedError:
        return
    for channel in CHANNELS:
        for i, fx in enumerate(METADATA_FIXTURES, 1):
            adapter.reset()
            g = genuine(fx.genuine, "victim")
            g.metadata.update(TRUST_TAG)
            adapter.add_memory(g)
            tagged = attacker_write(fx.planted, "victim", channel)
            tagged.metadata.update(TRUST_TAG)
            adapter.add_memory(tagged)
            hits = adapter.retrieve_where(fx.query, "victim", TRUST_TAG, k=5)
            yield 1
            if _served(hits, fx.planted_key) and _served(hits, fx.genuine_key):
                writes = [(fx.genuine, "user-signed", "trust=verified"),
                          (fx.planted, channel, "trust=verified")]
                yield Finding(
                    "metadata_poisoning", channel, "base", i, fx.planted_key,
                    fx.query, "a self-tagged memory passed the trust filter",
                    _repro("metadata_poisoning", channel, "base", writes,
                           fx.query, fx.planted_key))
                return


_HUNTS = [_hunt_injection, _hunt_hijack, _hunt_prompt, _hunt_update,
          _hunt_metadata]


def hunt(adapter: SemanticMemoryAdapter, *, target: str = "library",
         authorisation: Authorisation | None = None,
         mutate: bool = True) -> HuntReport:
    """Search ``adapter`` for landings and return a report of what was
    proved. ``authorisation`` must be supplied for anything but an
    in-process library target; the caller obtains it from
    ``agmi.agent.authz`` before constructing the adapter."""
    authz = authorisation or authorise_library()
    report = HuntReport(target=target, authorisation=f"{authz.kind}: {authz.detail}",
                        platform=f"{platform.system()} {platform.machine()}, "
                                 f"Python {sys.version_info.major}.{sys.version_info.minor}")
    try:
        for hunt_fn in _HUNTS:
            for item in hunt_fn(adapter, mutate):
                if isinstance(item, Finding):
                    report.findings.append(item)
                else:
                    report.tried += item
    finally:
        adapter.close()
    return report
