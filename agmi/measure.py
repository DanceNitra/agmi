# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Measure one target against the memory-specific attack family.

    python -m agmi.measure --target mem0 --embedder minilm
    python -m agmi.measure --target langgraph-store --embedder minilm
    python -m agmi.measure --target inspeximus

Prints the four cells for the target with the provenance line the adapter
reports (library version, embedder, which of the tool's optional ranking
signals were on, platform). That line is what goes next to the row in the
README, so a reader can reproduce the cell rather than take it on trust.

Targets that rank by an embedder are published only when measured with a
real sentence embedder (``--embedder minilm``); ``--embedder hash`` runs the
same code offline and is for exercising the adapter, not for publishing.
inspeximus ranks lexically at this store size and needs no embedder.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from agmi.adapters.semantic_base import SemanticMemoryAdapter
from agmi.attacks.memory_specific import ALL_MEMORY_ATTACKS, MemoryAttackResult


def run_memory_attacks(adapter: SemanticMemoryAdapter) -> list[MemoryAttackResult]:
    """Run the four memory-specific attacks against one adapter, in
    catalogue order. Each attack resets the adapter itself."""
    return [cls().run(adapter) for cls in ALL_MEMORY_ATTACKS]


def format_memory_row(label: str, results: list[MemoryAttackResult],
                      measured_on: str) -> str:
    lines = [f"target      {label}", f"measured on {measured_on}", ""]
    for r in results:
        lines.append(f"  {r.attack:28s} {r.status:12s} {r.detail or r.error}")
    return "\n".join(lines)


def _mem0(embedder: str):
    from agmi.adapters.mem0_semantic import Mem0SemanticAdapter
    from agmi.embedders import get_embedder
    return Mem0SemanticAdapter(get_embedder(embedder))


def _langgraph_store(embedder: str):
    from agmi.adapters.langgraph_store import LangGraphSqliteStoreAdapter
    from agmi.embedders import get_embedder
    return LangGraphSqliteStoreAdapter(get_embedder(embedder))


def _inspeximus(embedder: str):
    from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
    return InspeximusRecallAdapter()


#: Target name -> factory taking the embedder name. Add a line here when a
#: new semantic adapter lands so it gets the same command as the others.
TARGETS: dict[str, Callable[[str], SemanticMemoryAdapter]] = {
    "mem0": _mem0,
    "langgraph-store": _langgraph_store,
    "inspeximus": _inspeximus,
}


def measure(target: str, embedder: str = "minilm"):
    """Build the adapter for ``target`` and run the family against it.
    Returns ``(results, measured_on)``. Adapters that hold resources are
    closed afterwards."""
    try:
        factory = TARGETS[target]
    except KeyError:
        raise ValueError(
            f"unknown target {target!r}; choose one of "
            f"{', '.join(sorted(TARGETS))}") from None
    adapter = factory(embedder)
    try:
        results = run_memory_attacks(adapter)
        measured_on = adapter.measured_on() if hasattr(adapter, "measured_on") \
            else "not recorded by this adapter"
        return results, measured_on
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()


def main(argv: list[str] | None = None) -> int:
    from agmi.embedders import EMBEDDERS

    parser = argparse.ArgumentParser(
        prog="python -m agmi.measure",
        description="Run the memory-specific attacks against one target "
                    "and print its row with provenance.")
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--embedder", choices=sorted(EMBEDDERS),
                        default="minilm",
                        help="ignored by targets that do not rank by an "
                             "embedder")
    args = parser.parse_args(argv)
    try:
        results, measured_on = measure(args.target, args.embedder)
    except NotImplementedError as exc:
        print(f"cannot measure: {exc}", file=sys.stderr)
        return 2
    print(format_memory_row(args.target, results, measured_on))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
