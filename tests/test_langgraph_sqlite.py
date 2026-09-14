# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for the real LangGraph SqliteSaver.

These are measurements of the actual library, not a model of it. The
version is recorded so a future change in LangGraph that adds integrity
checking shows up as a test failure here, which is the signal we want.
"""

import importlib.metadata as md

import pytest

pytest.importorskip("langgraph.checkpoint.sqlite")

from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "langgraph-checkpoint-sqlite 3.1.1 / langgraph-checkpoint 4.2.0"


def _run_all():
    return {cls().name: cls().run(LangGraphSqliteAdapter())
            for cls in ALL_AT_REST_ATTACKS}


def test_langgraph_sqlite_accepts_every_at_rest_tamper():
    results = _run_all()
    for name, r in results.items():
        assert r.error is None, f"{name} errored: {r.error}"
        assert not r.detected, (
            f"{name}: LangGraph now detects this. Re-measure and update "
            f"the scorecard (last measured on {MEASURED_ON}, now "
            f"{md.version('langgraph-checkpoint-sqlite')})")


def test_forged_tip_becomes_the_resume_point():
    a = LangGraphSqliteAdapter()
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.forge_record(recs[-1]))
        a.reload()
        latest = a._saver.get({"configurable": {"thread_id": "agmi-thread"}})
        assert latest["channel_values"]["state"].startswith("agmi-TAMP-")
    finally:
        a.teardown()
