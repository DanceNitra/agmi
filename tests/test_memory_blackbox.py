# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the memory-blackbox memory.md
watcher with the agent process alive across the edit."""

import importlib.metadata as md

import pytest

pytest.importorskip("memory_blackbox")

from agmi.adapters.memory_blackbox import MemoryBlackboxMdAdapter  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "memory-blackbox 0.1.0"


def test_version_is_the_measured_one():
    assert md.version("memory-blackbox") == "0.1.0", (
        "memory-blackbox moved; re-measure and re-pin")


def test_every_edit_is_reported_on_scan():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(MemoryBlackboxMdAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected, f"{r.attack}: served as genuine on {MEASURED_ON}"


def test_detection_is_on_the_audit_not_the_read_path():
    a = MemoryBlackboxMdAdapter()
    assert a.detection_point == "audit"
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.mutate_payload(recs[2]))
        # the file serves the edit as-is
        assert "[TAMPERED]" in a.read_all_raw()[2].fields["line"]
        assert a.verify() is False
        assert "out-of-band write" in (a.verify_detail or "")
    finally:
        a.teardown()
