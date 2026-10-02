# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for LangGraph RedisSaver on Redis 8.

Runs only when AGMI_REDIS_URI points at a Redis with the JSON and search
modules; the row uses its own key prefix and deletes its keys after."""

import importlib.metadata as md
import os

import pytest

pytest.importorskip("langgraph.checkpoint.redis")
if not os.environ.get("AGMI_REDIS_URI"):
    pytest.skip("AGMI_REDIS_URI not set", allow_module_level=True)

from agmi.adapters.langgraph_redis import LangGraphRedisAdapter  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "langgraph-checkpoint-redis 0.5.2"


def test_version_is_the_measured_one():
    assert md.version("langgraph-checkpoint-redis") == "0.5.2", (
        "langgraph-checkpoint-redis moved; re-measure and re-pin")


def test_every_edit_is_served():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(LangGraphRedisAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert not r.detected, f"{r.attack}: now refused or reported on {MEASURED_ON}; re-pin"


def test_dangling_pointer_reads_as_an_empty_thread():
    """Newest document deleted, pointer left alone: get() returns None,
    list() still returns the older checkpoints. A loss, not a detection."""
    a = LangGraphRedisAdapter()
    a.setup()
    try:
        a.seed(5)
        keys = a._doc_keys(a.thread)
        a._r.delete(keys[-1])
        a.reload()
        cfg = {"configurable": {"thread_id": a.thread}}
        assert a._saver.get(cfg) is None
        assert len(list(a._saver.list(cfg))) == 4
    finally:
        a.teardown()


def test_moved_pointer_serves_the_rollback():
    a = LangGraphRedisAdapter()
    a.setup()
    try:
        a.seed(5)
        a.delete_raw(4)
        a.reload()
        got = a._saver.get({"configurable": {"thread_id": a.thread}})
        assert got["channel_values"]["state"] == "agmi-seed-3"
    finally:
        a.teardown()
