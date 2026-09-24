# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""``python -m agmi.agent --target <name>``: hunt a library target and print
a report. Network targets are added in the live tier; the gate in
``agmi.agent.authz`` already refuses any host the operator has not cleared.
"""

from __future__ import annotations

import argparse
import sys

from agmi.agent import hunt
from agmi.agent.report import to_json, to_text
from agmi.embedders import EMBEDDERS
from agmi.measure import TARGETS


def _library_target(name: str, embedder: str):
    if name == "naive":
        from agmi.adapters.naive_memory import NaiveMemoryAdapter
        return NaiveMemoryAdapter()
    if name == "defended":
        from agmi.adapters.defended_memory import DefendedMemoryAdapter
        return DefendedMemoryAdapter()
    if name in TARGETS:
        return TARGETS[name](embedder)
    raise SystemExit(f"unknown target {name!r}; choose one of: naive, "
                     f"defended, {', '.join(sorted(TARGETS))}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agmi.agent")
    ap.add_argument("--target", required=True,
                    help="library target: naive, defended, or a scorecard "
                         "target (mem0, langgraph-store, inspeximus, "
                         "letta-archival)")
    ap.add_argument("--embedder", choices=sorted(EMBEDDERS), default="minilm")
    ap.add_argument("--no-mutate", action="store_true",
                    help="base attacks only, no content-evasion mutations")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    adapter = _library_target(args.target, args.embedder)
    report = hunt(adapter, target=args.target, mutate=not args.no_mutate)
    out = to_json(report) if args.json else to_text(report)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
