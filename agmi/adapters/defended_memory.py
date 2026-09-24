# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""A defended reference store: the naive store plus the three defences the
memory-specific attacks call for, to show that every cell is winnable.

This is a model, not a product. It exists for the same reason the OpenFang
hash-chain model exists on the at-rest table: a benchmark nobody can pass
proves nothing, so here is the smallest store that passes all four, with
each defence named and visible.

1. Provenance, bound by a key. Every memory carries the channel it came in
   on and a signature by the writer's key (``agmi.signing``). Retrieval for
   the agent's context serves only memories whose signature verifies
   against the user's key; a label alone buys nothing, since whoever
   writes the memory writes the label. That keeps out an API attacker's
   planted fact on both the external and the laundered channel. It cannot
   keep out content that came through the agent itself and was signed by
   it: a plausible fact wearing a valid signature is indistinguishable from
   a genuine one, and that is the finding on the agent-laundered channel.
2. Quarantine at write. A record that reads as an instruction to the model
   (see ``agmi.checks.looks_like_instruction``) is stored but flagged, and
   flagged records are never served. That is what keeps a hidden
   instruction out of context.
3. A stuffing check at write. A record whose tokens repeat far beyond a
   normal sentence (``agmi.checks.looks_stuffed``) is flagged and served
   only after every unflagged candidate. That is what keeps a padded entry
   from taking a slot.

User isolation is inherited from the naive store. Ranking is token overlap,
as in the naive store, so the comparison with the undefended row isolates
the effect of the three defences.
"""

from __future__ import annotations

from dataclasses import dataclass

from agmi.adapters.naive_memory import NaiveMemoryAdapter, _tokens
from agmi.adapters.semantic_base import MemoryItem, Retrieved
from agmi.checks import looks_like_instruction, looks_stuffed
from agmi.signing import KEYRING


@dataclass
class _Stored:
    item: MemoryItem
    quarantined: bool
    stuffed: bool


class DefendedMemoryAdapter(NaiveMemoryAdapter):
    """The naive store with provenance, quarantine and a stuffing check."""

    def __init__(self):
        super().__init__(enforce_user_scope=True)
        self.name = "reference-defended"
        self._stored: list[_Stored] = []

    def reset(self) -> None:
        super().reset()
        self._stored = []

    def add_memory(self, item: MemoryItem) -> None:
        self._stored.append(_Stored(
            item=item,
            quarantined=looks_like_instruction(item.text),
            stuffed=looks_stuffed(item.text),
        ))

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        q = _tokens(query)
        scored: list[tuple[int, float, MemoryItem]] = []
        for rec in self._stored:
            item = rec.item
            if item.user_id != user_id:
                continue                     # isolation
            if rec.quarantined:
                continue                     # instruction-shaped: never served
            if not KEYRING.verify(item.user_id, item.source, item.text,
                                  item.signature):
                continue                     # unverifiable writer: not trusted context
            overlap = len(q & _tokens(item.text))
            if overlap == 0:
                continue
            score = overlap / (len(q) or 1)
            tier = 1 if rec.stuffed else 0   # stuffed records rank last
            scored.append((tier, score, item))
        scored.sort(key=lambda s: (s[0], -s[1]))
        return [Retrieved(text=i.text, user_id=i.user_id, score=sc)
                for _, sc, i in scored[:k]]

    def measured_on(self) -> str:
        return ("reference store with signed-write provenance, write-time quarantine "
                "of instruction-shaped records and a stuffing check; token-overlap "
                "ranking")
