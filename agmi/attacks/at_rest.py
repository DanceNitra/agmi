# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The five at-rest attacks.

All five assume the attacker has gained write access to the backing store
(the SQLite file, the Postgres rows, the JSON blob) but NOT access to the
tool's own signing keys or in-process integrity logic. This is the standard
"database compromise / privileged write at rest" threat model behind the
real LangGraph checkpointer CVEs.

Each attack mutates the raw store, then the harness reloads the tool and
asks whether it noticed.
"""

from __future__ import annotations

from agmi.adapters.base import MemoryAdapter, Record
from agmi.attacks.base import Attack


class TamperAttack(Attack):
    """Modify the contents of one existing entry in place."""

    name = "tamper"
    description = "Alter the payload of a stored entry without touching its links."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to tamper with")
        target = records[len(records) // 2]
        # The adapter knows how to change meaning without breaking encoding.
        adapter.write_raw(adapter.mutate_payload(target))


class TruncateAttack(Attack):
    """Delete entries from the END of the chain.

    This is the one that slipped past OpenFang: forward-only link checks
    stay valid because the surviving prefix still chains correctly.
    """

    name = "truncate"
    description = "Remove the most recent entries from the tail of the store."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to truncate")
        # Drop the last two entries, tail first, so adapters that address
        # rows by ordinal position stay valid after the first delete.
        for rec in reversed(records[-2:]):
            adapter.delete_raw(rec.seq)


class DeleteMiddleAttack(Attack):
    """Remove a single entry from the MIDDLE of the chain."""

    name = "delete_middle"
    description = "Remove one interior entry, leaving a gap in the sequence."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 3:
            raise RuntimeError("need at least 3 records to delete a middle one")
        victim = records[len(records) // 2]
        adapter.delete_raw(victim.seq)


class ReorderAttack(Attack):
    """Swap the position of two adjacent entries."""

    name = "reorder"
    description = "Exchange two entries so events appear in the wrong order."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to reorder")
        i = len(records) // 2
        a, b = records[i - 1], records[i]
        a_seq = a.seq
        b_seq = b.seq
        a.seq, b.seq = b_seq, a_seq
        adapter.write_raw(a)
        adapter.write_raw(b)


class ForgeAttack(Attack):
    """Insert a brand-new entry that mimics a legitimate one."""

    name = "forge"
    description = "Append a fabricated entry crafted to look authentic."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to base a forgery on")
        adapter.write_raw(adapter.forge_record(records[-1]))


ALL_AT_REST_ATTACKS: list[type[Attack]] = [
    TamperAttack,
    TruncateAttack,
    DeleteMiddleAttack,
    ReorderAttack,
    ForgeAttack,
]
