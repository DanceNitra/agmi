# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for langgraph-ledger over SqliteSaver.

verify_thread() is the audit. The version is recorded so a release that
logs forged checkpoints or covers metadata shows up here as a failure.
"""

import importlib.metadata as md

import pytest

pytest.importorskip("langgraph_ledger")
pytest.importorskip("langgraph.checkpoint.sqlite")

from agmi.adapters.langgraph_ledger import LangGraphLedgerAdapter  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "langgraph-ledger 0.3.0"

# True = reported on audit, False = served as genuine.
EXPECTED = {
    "tamper": True,
    "truncate": True,
    "delete_middle": True,
    "reorder": True,
    "forge": False,
    "cross_replay": True,
    "rollback_replay": True,
    "metadata_tamper": False,
}


def test_version_is_the_measured_one():
    assert md.version("langgraph-ledger") == "0.3.0", (
        "langgraph-ledger moved; re-measure and re-pin")


def test_the_scorecard_row_is_as_measured():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(LangGraphLedgerAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected == EXPECTED[r.attack], (
            f"{r.attack}: measured {'reported' if r.detected else 'accepted'}, "
            f"pinned {'reported' if EXPECTED[r.attack] else 'accepted'} on {MEASURED_ON}")


def test_detection_is_on_the_audit_not_the_read_path():
    """The inner SqliteSaver still serves the tampered head on resume."""
    from agmi.adapters.langgraph_sqlite import THREAD
    a = LangGraphLedgerAdapter()
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.mutate_payload(recs[2]))
        a.reload()
        served = a._saver.get({"configurable": {"thread_id": THREAD}})
        assert served is not None
        assert a.verify() is False
        assert "drifted" in (a.verify_detail or "")
    finally:
        a.teardown()
