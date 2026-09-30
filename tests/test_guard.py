# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Control C3: an edit that does not land as intended is an ERROR cell,
never a pass and never a fail.

The bug this guards against was found by the inspeximus maintainer in
issue #5: the T6 victim pool was read from both contexts, so the donor was
copied onto itself and a no-op scored as "accepted". These tests run every
attack on a plain in-memory store that has no integrity at all (so every
real edit is accepted), then break the store's adapter in the ways that
made an edit a no-op and check that the guard turns each into ERROR.
"""

from __future__ import annotations

import copy

from agmi.adapters.base import MemoryAdapter, Record
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS, CrossContextReplayAttack, MetadataTamperAttack,
    ReorderAttack, RollbackReplayAttack, TamperAttack,
)

CTX, OTHER = "ctx-A", "ctx-B"


class PlainStore(MemoryAdapter):
    """Rows of {id, owner, text, meta}. Accepts everything; every edit is
    real. The guard must pass all eight."""

    name = "plain-store"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self.rows: list[dict] = []
        self._next = 0

    def setup(self):
        self.rows, self._next = [], 0

    def teardown(self):
        pass

    def _add(self, owner, text):
        self.rows.append({"id": f"r{self._next}", "owner": owner, "text": text,
                          "meta": {"source": "user", "ts": self._next}})
        self._next += 1

    def seed(self, n):
        for i in range(n):
            self._add(CTX, f"a-{i}")

    def seed_other(self, n):
        for i in range(n):
            self._add(OTHER, f"b-{i}")

    def _ctx(self, owner):
        return [r for r in self.rows if r["owner"] == owner]

    def read_all_raw(self):
        return [Record(seq=i, fields=copy.deepcopy(r))
                for i, r in enumerate(self._ctx(CTX))]

    def read_other_raw(self):
        return [Record(seq=i, fields=copy.deepcopy(r))
                for i, r in enumerate(self._ctx(OTHER))]

    def _slot(self, seq):
        return self._ctx(CTX)[seq]

    def write_raw(self, record):
        f = record.fields
        mine = self._ctx(CTX)
        if record.seq < len(mine):
            target = mine[record.seq]
            target["text"] = f["text"]
            target["meta"] = f["meta"]
        else:
            self.rows.append({**f, "id": f"r{self._next}"})
            self._next += 1

    def delete_raw(self, seq):
        self.rows.remove(self._slot(seq))

    def replay_onto(self, victim_seq, donor):
        target = self._slot(victim_seq)
        target["text"] = donor.fields["text"]
        target["meta"] = copy.deepcopy(donor.fields["meta"])

    def read_meta(self, seq):
        return dict(self._slot(seq)["meta"])

    def write_meta(self, seq, meta):
        self._slot(seq)["meta"] = dict(meta)

    def reload(self):
        pass

    def verify(self):
        return True

    def mutate_payload(self, record):
        record.fields["text"] += " [TAMPERED]"
        return record

    def forge_record(self, template):
        f = copy.deepcopy(template.fields)
        f["text"] = "forged"
        return Record(seq=template.seq + 1, fields=f)

    # guard hooks
    def identity_of(self, record):
        return record.fields["id"]

    def payload_of(self, record):
        return record.fields["text"]

    def owner_of(self, record):
        return record.fields["owner"]


def test_every_real_edit_passes_the_guard_and_is_accepted():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(PlainStore())
        assert r.guard is None, f"{cls.name}: guard fired on a real edit: {r.guard}"
        assert r.status == "VULNERABLE", f"{cls.name}: {r.status}"


class BothContexts(PlainStore):
    """The issue #5 bug: the victim pool is read from the whole store."""
    name = "both-contexts"

    def read_all_raw(self):
        return [Record(seq=i, fields=copy.deepcopy(r))
                for i, r in enumerate(self.rows)]

    def _slot(self, seq):
        return self.rows[seq]


def test_cross_replay_onto_itself_is_an_error_not_a_verdict():
    r = CrossContextReplayAttack().run(BothContexts())
    assert r.status == "ERROR"
    assert r.detected is False
    assert "second context changed the first context" in r.guard


class ReplayKeepsOwnText(PlainStore):
    name = "replay-noop"

    def replay_onto(self, victim_seq, donor):
        pass


def test_replay_that_changes_nothing_is_an_error():
    for cls in (CrossContextReplayAttack, RollbackReplayAttack):
        r = cls().run(ReplayKeepsOwnText())
        assert r.status == "ERROR", f"{cls.name}: {r.status}"
        assert "to change" in r.guard


class ReplayMovesOwner(PlainStore):
    """Replay copies the donor's owner too: an owner move, not a replay."""
    name = "replay-moves-owner"

    def replay_onto(self, victim_seq, donor):
        target = self._slot(victim_seq)
        target["text"] = donor.fields["text"]
        target["owner"] = donor.fields["owner"]


def test_replay_that_moves_the_owner_is_an_error():
    r = CrossContextReplayAttack().run(ReplayMovesOwner())
    assert r.status == "ERROR"


class WriteByIdOnly(PlainStore):
    """The Mem0 shape before the fix: write_raw ignores seq and writes the
    record back under its own id, so a reorder changes nothing."""
    name = "write-by-id"

    def write_raw(self, record):
        f = record.fields
        for r in self.rows:
            if r["id"] == f["id"]:
                r["text"] = f["text"]
                return
        self.rows.append(dict(f))


def test_reorder_that_changes_nothing_is_an_error():
    r = ReorderAttack().run(WriteByIdOnly())
    assert r.status == "ERROR"
    assert "changed []" in r.guard


class TamperNoop(PlainStore):
    name = "tamper-noop"

    def mutate_payload(self, record):
        return record


def test_tamper_that_changes_nothing_is_an_error():
    r = TamperAttack().run(TamperNoop())
    assert r.status == "ERROR"


class MetaWriteDropped(PlainStore):
    name = "meta-dropped"

    def write_meta(self, seq, meta):
        pass


def test_metadata_write_that_does_not_stick_is_an_error():
    r = MetadataTamperAttack().run(MetaWriteDropped())
    assert r.status == "ERROR"
    assert "reads back unchanged" in r.guard


def test_error_is_never_a_pass_in_the_printed_words():
    from agmi.check import verdict
    from agmi.full_runner import _verdict as _word
    r = CrossContextReplayAttack().run(BothContexts())
    assert _word(r.status, False, "read") == "error"
    assert verdict(r, BothContexts()) == "ERROR"
