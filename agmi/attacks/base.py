# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The attack contract and its result type.

Every attack does the same three things:
  1. seed a clean store through the adapter,
  2. tamper with the raw store in one specific way,
  3. reload and ask the tool whether it noticed.

The attack does not know or care which tool it is hitting. It only uses
the MemoryAdapter interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from agmi.adapters.base import MemoryAdapter
from agmi.attacks.guard import GuardFailed, Snap, snapshot


@dataclass
class AttackResult:
    """Outcome of one attack against one tool.

    detected=True  -> the tool caught the tampering (good; the tool is safe
                      against this attack).
    detected=False -> the tool accepted the tampered store silently (bad;
                      this is a finding).
    error          -> set when the attack could not run to completion
                      (e.g. the adapter could not reach the raw store); the
                      cell is scored as "n/a", never as a pass.
    """

    attack: str
    tool: str
    detected: bool
    detail: str = ""
    error: str | None = None
    #: Version of the attack definition that produced this result. Bumped
    #: whenever a fixture or verdict rule changes, so cells from different
    #: reports are never compared as if the attack had stood still.
    version: int = 1
    #: Who the attacker is: "store-access" (edits the files) here.
    attacker: str = "store-access"
    #: Set when the edit did not land as intended (control C3 failed). The
    #: cell is an ERROR: the harness, not the tool, is at fault, and no
    #: verdict exists for it.
    guard: str | None = None

    @property
    def status(self) -> str:
        if self.guard is not None:
            return "ERROR"
        if self.error is not None:
            return "n/a"
        return "safe" if self.detected else "VULNERABLE"


class Attack(ABC):
    """Base class for a single at-rest attack."""

    #: Short attack name for the scorecard, e.g. "truncate".
    name: str
    #: One-line description of what this attack does.
    description: str

    #: How many legitimate entries to seed before attacking.
    seed_count: int = 5
    #: Attack definition version. Bump when the fixture or the verdict rule
    #: changes; results and reports carry it.
    version: int = 1

    def __init__(self) -> None:
        #: What tamper() decided (which slot, which donor), for check_landed.
        self._ctx: dict = {}

    def run(self, adapter: MemoryAdapter) -> AttackResult:
        """Full attack lifecycle against one adapter. Never raises: any
        failure to execute is captured as an errored result so one broken
        adapter can't abort the whole scorecard run."""
        try:
            adapter.setup()
            adapter.seed(self.seed_count)
            # Control 1: the clean store must verify, or the test is invalid.
            if not adapter.verify():
                return AttackResult(
                    self.name, adapter.name, detected=False,
                    error="clean store failed to verify before attack",
                    version=self.version,
                )
            # Control 2: a reload with no edit must still verify. Without
            # this, a tool that cannot reopen its own store (a lock, a
            # flaky restart, a refusal of any reopened store) would score
            # "detected" on every edit while detecting nothing.
            adapter.reload()
            if not adapter.verify():
                return AttackResult(
                    self.name, adapter.name, detected=False,
                    error=("store failed to verify after a reload with no "
                           "edit, so no verdict can be taken"
                           + self._why(adapter)),
                    version=self.version,
                )
            # Control 3: the edit must land as intended. Snapshot before
            # and after, and let the attack check the difference against
            # its own intent. A no-op or a misplaced edit is an ERROR
            # cell, never a pass or a fail (see agmi.attacks.guard).
            self._ctx = {}
            before = snapshot(adapter, adapter.read_all_raw())
            self.tamper(adapter)
            after = snapshot(adapter, adapter.read_all_raw())
            try:
                self.check_landed(adapter, before, after)
            except GuardFailed as gf:
                return AttackResult(
                    self.name, adapter.name, detected=False,
                    guard=f"edit did not land: {gf}", version=self.version,
                )
            adapter.reload()
            detected = not adapter.verify()
            return AttackResult(
                self.name, adapter.name, detected=detected,
                detail=self.detail_on(detected) + (self._why(adapter) if detected else ""),
                version=self.version,
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            return AttackResult(
                self.name, adapter.name, detected=False, error=str(exc),
                version=self.version,
            )
        finally:
            try:
                adapter.teardown()
            except Exception:  # noqa: BLE001
                pass

    @abstractmethod
    def tamper(self, adapter: MemoryAdapter) -> None:
        """Perform this attack's specific mutation on the raw store."""

    def check_landed(self, adapter: MemoryAdapter, before: list[Snap],
                     after: list[Snap]) -> None:
        """Raise GuardFailed unless the store changed exactly the way this
        attack intended. Every attack overrides this; the default refuses
        to score at all, so a new attack cannot skip the control."""
        raise GuardFailed(f"{self.name} defines no landed check")

    def detail_on(self, detected: bool) -> str:
        return "detected on reload" if detected else "accepted silently"

    @staticmethod
    def _why(adapter: MemoryAdapter) -> str:
        """The adapter's own account of why verify() said no, so a reader
        can tell a deliberate integrity refusal from an incidental crash."""
        why = getattr(adapter, "verify_detail", None)
        return f" ({why})" if why else ""
