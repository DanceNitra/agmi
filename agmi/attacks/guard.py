# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Control C3: the edit must have landed the way the attack intended.

An at-rest verdict is only meaningful if the store actually changed in the
way the edit describes. An edit that touches nothing, or touches the wrong
record, would still be read back cleanly, and the cell would read as
"accepted" on a plain store or "reported" on a defended one. Neither is a
measurement. So every attack snapshots the store before and after its
edit and checks the difference against its own intent. A failed check is
an ERROR cell, never a pass or a fail.

The snapshot is built through three adapter hooks, each with a default:
identity_of (the slot a record occupies), payload_of (its content bytes)
and owner_of (the context it belongs to). Adapters that model a second
context override all three, because the replay checks depend on them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from agmi.adapters.base import MemoryAdapter, Record


class GuardFailed(RuntimeError):
    """The edit did not land as intended; no verdict may be taken."""


@dataclass(frozen=True)
class Snap:
    identity: str
    payload: str
    owner: str | None
    fp: str  # hash of every field, the "nothing else moved" check


def _canon(value) -> str:
    return json.dumps(value, sort_keys=True, default=repr, ensure_ascii=False)


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def snap_record(adapter: MemoryAdapter, rec: Record) -> Snap:
    return Snap(
        identity=str(adapter.identity_of(rec)),
        payload=_h(adapter.payload_of(rec)),
        owner=adapter.owner_of(rec),
        fp=_h(_canon(rec.fields)),
    )


def snapshot(adapter: MemoryAdapter, records: list[Record]) -> list[Snap]:
    return [snap_record(adapter, r) for r in records]


def changed_positions(before: list[Snap], after: list[Snap]) -> list[int]:
    if len(before) != len(after):
        raise GuardFailed(f"record count moved from {len(before)} to {len(after)}")
    return [i for i, (b, a) in enumerate(zip(before, after)) if b.fp != a.fp]


def expect(cond: bool, message: str) -> None:
    if not cond:
        raise GuardFailed(message)


def same_records(a: list[Snap], b: list[Snap]) -> bool:
    return [s.fp for s in a] == [s.fp for s in b]
