# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The LangGraph encrypted-checkpointer replay. Encryption must hold at
rest (the raw row is not the plaintext), and on the measured version the
same-key cross-thread replay is accepted. Skips cleanly without LangGraph
or pycryptodome."""

import pytest

pytest.importorskip("langgraph.checkpoint.sqlite")
pytest.importorskip("Crypto")

from agmi.adapters.langgraph_encrypted import (  # noqa: E402
    ATTACKER_VALUE, VICTIM_VALUE, langgraph_version, measure_replay,
)

MEASURED_ON = "langgraph-checkpoint 4.2.0"


def test_encryption_holds_at_rest_but_the_replay_is_accepted():
    r = measure_replay()
    assert r["confidential_at_rest"], "the plaintext was found in the raw row"
    assert r["victim_reads"] in (VICTIM_VALUE, ATTACKER_VALUE)
    assert r["accepted"] is True, (
        f"the replay was rejected on langgraph-checkpoint "
        f"{langgraph_version()} (measured on {MEASURED_ON}); if a fix landed, "
        f"this is the good kind of failure and the row should be re-measured")
    assert r["victim_reads"] == ATTACKER_VALUE
