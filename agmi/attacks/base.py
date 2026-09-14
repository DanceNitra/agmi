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

    @property
    def status(self) -> str:
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

    def run(self, adapter: MemoryAdapter) -> AttackResult:
        """Full attack lifecycle against one adapter. Never raises: any
        failure to execute is captured as an errored result so one broken
        adapter can't abort the whole scorecard run."""
        try:
            adapter.setup()
            adapter.seed(self.seed_count)
            # Sanity: the clean store must verify OK, or the test is invalid.
            if not adapter.verify():
                return AttackResult(
                    self.name, adapter.name, detected=False,
                    error="clean store failed to verify before attack",
                )
            self.tamper(adapter)
            adapter.reload()
            detected = not adapter.verify()
            return AttackResult(
                self.name, adapter.name, detected=detected,
                detail=self.detail_on(detected),
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            return AttackResult(
                self.name, adapter.name, detected=False, error=str(exc),
            )
        finally:
            try:
                adapter.teardown()
            except Exception:  # noqa: BLE001
                pass

    @abstractmethod
    def tamper(self, adapter: MemoryAdapter) -> None:
        """Perform this attack's specific mutation on the raw store."""

    def detail_on(self, detected: bool) -> str:
        return "detected on reload" if detected else "accepted silently"
