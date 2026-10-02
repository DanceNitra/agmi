# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for LangGraph PostgresSaver.

Runs only when AGMI_POSTGRES_URI points at a reachable PostgreSQL; the row
creates and drops its own schema, so any database will do."""

import importlib.metadata as md
import os

import pytest

pytest.importorskip("langgraph.checkpoint.postgres")
if not os.environ.get("AGMI_POSTGRES_URI"):
    pytest.skip("AGMI_POSTGRES_URI not set", allow_module_level=True)

from agmi.adapters.langgraph_postgres import LangGraphPostgresAdapter, THREAD  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "langgraph-checkpoint-postgres 3.1.2"


def test_version_is_the_measured_one():
    assert md.version("langgraph-checkpoint-postgres") == "3.1.2", (
        "langgraph-checkpoint-postgres moved; re-measure and re-pin")


def test_every_edit_is_served():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(LangGraphPostgresAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert not r.detected, f"{r.attack}: now refused or reported on {MEASURED_ON}; re-pin"


def test_tampered_head_is_the_state_served():
    a = LangGraphPostgresAdapter()
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.mutate_payload(recs[4]))
        a.reload()
        served = a._saver.get({"configurable": {"thread_id": THREAD}})
        assert served["channel_values"]["state"] == "agmi-TAMP-4"
    finally:
        a.teardown()
