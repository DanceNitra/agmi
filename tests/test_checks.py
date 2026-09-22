# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The two text checks must fire on every attacker text in the fixtures and
on none of the genuine text beside it. If a fixture is added that trips
this, the fixture or the check is wrong, not the tool being scored."""

from agmi.attacks.memory_specific import (
    BLEED_FIXTURES, HIJACK_FIXTURES, INJECTION_FIXTURES,
    PROMPT_INJECTION_FIXTURES,
)
from agmi.checks import looks_like_instruction, looks_stuffed


def test_instruction_check_fires_on_every_payload_and_no_genuine_text():
    for fx in PROMPT_INJECTION_FIXTURES:
        assert looks_like_instruction(fx.payload), fx.payload
        assert not looks_like_instruction(fx.genuine), fx.genuine
    for fx in INJECTION_FIXTURES:
        assert not looks_like_instruction(fx.genuine)
        assert not looks_like_instruction(fx.planted), (
            "a planted fact must read as a fact, not an instruction, or the "
            "injection cell would be measuring quarantine")
    for fx in BLEED_FIXTURES:
        assert not looks_like_instruction(fx.secret)
    for fx in HIJACK_FIXTURES:
        for g in fx.genuine:
            assert not looks_like_instruction(g)


def test_stuffing_check_fires_on_every_stuffed_entry_and_no_genuine_text():
    for fx in HIJACK_FIXTURES:
        assert looks_stuffed(fx.entry), fx.entry
        for g in fx.genuine:
            assert not looks_stuffed(g), g
    for fx in INJECTION_FIXTURES + PROMPT_INJECTION_FIXTURES:
        assert not looks_stuffed(fx.genuine)
