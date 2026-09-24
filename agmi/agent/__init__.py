# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The memory agent: search a target for a way to get a false memory served
as trusted, prove each one, and report only what landed."""

from agmi.agent.hunter import Finding, hunt

__all__ = ["Finding", "hunt"]
