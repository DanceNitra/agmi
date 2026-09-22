# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Tests that pin the expected at-rest scorecard for OpenFang.

These lock in the core claim of the suite: a forward-only hash chain
(pre-fix OpenFang) catches modification but NOT tail-truncation, and the
tip-persistence fix closes exactly that one gap without weakening the rest.
"""

from agmi.adapters.openfang import OpenFangAdapter
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS,
)


def _run_all(adapter):
    return {cls().name: cls().run(adapter) for cls in ALL_AT_REST_ATTACKS}


def test_prefix_openfang_misses_only_truncation():
    results = _run_all(OpenFangAdapter(strict_tip=False))
    assert results["tamper"].detected
    assert results["delete_middle"].detected
    assert results["reorder"].detected
    assert results["forge"].detected
    # The one real gap: truncation slips past a forward-only walk.
    assert not results["truncate"].detected


def test_fixed_openfang_catches_everything():
    results = _run_all(OpenFangAdapter(strict_tip=True))
    for name, r in results.items():
        assert r.detected, f"fixed OpenFang should detect {name}"


def test_no_attack_errors_on_openfang():
    for strict in (False, True):
        for name, r in _run_all(OpenFangAdapter(strict_tip=strict)).items():
            assert r.error is None, f"{name} errored: {r.error}"


def test_clean_store_verifies_before_attack():
    a = OpenFangAdapter(strict_tip=True)
    a.setup()
    a.seed(5)
    assert a.verify() is True
    a.teardown()
