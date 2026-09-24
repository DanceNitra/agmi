# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Turn a hunt report into text a person reads and a fixture the benchmark
can adopt. Only proven findings appear; a target with no findings says so."""

from __future__ import annotations

import json

from agmi.agent.hunter import HuntReport


def to_text(report: HuntReport) -> str:
    lines = [
        f"agmi hunt report: {report.target}",
        f"authorisation: {report.authorisation}",
        f"platform: {report.platform}",
        f"attempts: {report.attempts if hasattr(report, 'attempts') else report.tried}",
        "",
    ]
    if not report.findings:
        lines.append("No landing found. Every attack, channel and mutation "
                     "in the default search was kept out of trusted retrieval.")
        return "\n".join(lines) + "\n"
    lines.append(f"{len(report.findings)} finding(s), each proven and "
                 f"reproducible:")
    for n, f in enumerate(report.findings, 1):
        lines += ["", f"[{n}] {f.attack}  ({f.detail})",
                  f"    channel: {f.channel}   mutation: {f.mutation}   "
                  f"fixture: {f.fixture}",
                  f"    proof: the memory served for {f.query!r} contained "
                  f"{f.key!r}", "    reproduce:"]
        lines += [f"      {step}" for step in f.repro]
    return "\n".join(lines) + "\n"


def to_json(report: HuntReport) -> str:
    return json.dumps(report.as_dict(), indent=2) + "\n"
