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
    ap.add_argument("--families", default="front-door",
                    help="comma-separated: front-door, at-rest (default "
                         "front-door). at-rest runs the nine storage edits "
                         "against the target's store.")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    families = [f.strip() for f in args.families.split(",") if f.strip()]
    unknown = [f for f in families if f not in ("front-door", "at-rest")]
    if unknown:
        raise SystemExit(f"unknown families: {', '.join(unknown)}; "
                         f"choose from front-door, at-rest")

    out_parts = []
    if "front-door" in families:
        try:
            adapter = _library_target(args.target, args.embedder)
        except SystemExit as e:
            if len(families) == 1:
                raise
            out_parts.append(f"front-door: skipped ({e})\n")
        else:
            report = hunt(adapter, target=args.target, mutate=not args.no_mutate)
            out_parts.append(to_json(report) if args.json else to_text(report))
    if "at-rest" in families:
        from agmi.agent.at_rest_hunt import hunt_at_rest, at_rest_target
        from agmi.agent.report import at_rest_to_json, at_rest_to_text
        a = at_rest_target(args.target)
        authz_line, findings = hunt_at_rest(a, target=args.target)
        out_parts.append(at_rest_to_json(args.target, authz_line, findings)
                         if args.json
                         else at_rest_to_text(args.target, authz_line, findings))
    sys.stdout.write("\n".join(out_parts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
