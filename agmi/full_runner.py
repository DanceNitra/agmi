# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Full scorecard across both attack families.

At-rest attacks (storage tampering) apply to any persisted store. Memory
attacks (injection, bleed, hijack, indirect injection) apply only to tools
that do user-scoped semantic retrieval. A tool that lacks one surface simply
scores n/a there, which is itself informative: an audit log cannot be
memory-injected; a bare vector store has no chain to truncate. LangGraph
gets two rows because its checkpointer (at rest) and its long-term store
(retrieval) are different components.

The checkedAt column names the detection point an adapter measures: "read"
means verify() is the tool's read path, the call that returns memories to the
agent; "audit" means verify() is a separate integrity call the operator has to
make, and the read path still serves the altered data. A detection on an audit
call prints "reported" rather than "safe" so the two are never read as the
same guarantee.
"""

from __future__ import annotations


def _mem0_semantic():
    """The memory-specific adapter for the Mem0 row, or None.

    Those cells are published only when measured with a real sentence
    embedder, so the row gets its semantic adapter only if
    sentence-transformers is installed and the model can be loaded. Without
    it the memory-specific columns stay n/a rather than being measured with
    the offline hashing stand-in, which would measure this suite, not Mem0.
    """
    try:
        from agmi.adapters.mem0_semantic import Mem0SemanticAdapter
        from agmi.embedders import SentenceTransformerEmbedder
        return Mem0SemanticAdapter(SentenceTransformerEmbedder())
    except (ImportError, NotImplementedError, OSError):
        return None


def _langgraph_store_semantic():
    """The LangGraph long-term store row, or None. Same rule as Mem0: its
    cells depend on ranking, so the row appears only with a real sentence
    embedder available."""
    try:
        from agmi.adapters.langgraph_store import LangGraphSqliteStoreAdapter
        from agmi.embedders import SentenceTransformerEmbedder
        return LangGraphSqliteStoreAdapter(SentenceTransformerEmbedder())
    except (ImportError, NotImplementedError, OSError):
        return None


def full_scorecard() -> str:
    from agmi.adapters.openfang import OpenFangAdapter
    from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter
    lg_store = _langgraph_store_semantic()
    try:
        from agmi.adapters.mem0_at_rest import Mem0AtRestAdapter
        mem0_row = ("mem0-qdrant-local", Mem0AtRestAdapter(), _mem0_semantic())
    except ImportError:
        mem0_row = None
    try:
        from agmi.adapters.letta_block_history import LettaBlockHistoryAdapter
        letta_row = ("letta-block-history", LettaBlockHistoryAdapter(), None)
    except ImportError:
        letta_row = None
    try:
        import inspeximus  # noqa: F401 - the adapter imports it lazily, so probe for it here
        from agmi.adapters.inspeximus_rows import (InspeximusDefaultAdapter, InspeximusRowsSidecarAdapter,
                                                   InspeximusRowsSidecarHeadAdapter)
        from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
        # recall ranks lexically at these sizes, so the default row's memory
        # cells need no embedder and run everywhere; receipts do not take
        # part in ranking, so the two receipts rows keep n/a there.
        inspeximus_rows = [("inspeximus-default", InspeximusDefaultAdapter(), InspeximusRecallAdapter()),
                           ("inspeximus-rcpt+dir", InspeximusRowsSidecarAdapter(), None),
                           ("inspeximus-rcpt+dir+home", InspeximusRowsSidecarHeadAdapter(), None)]
    except ImportError:
        inspeximus_rows = []
    from agmi.adapters.naive_memory import NaiveMemoryAdapter
    from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS
    from agmi.attacks.memory_specific import ALL_MEMORY_ATTACKS

    at_rest = [c() for c in ALL_AT_REST_ATTACKS]
    mem = [c() for c in ALL_MEMORY_ATTACKS]
    all_names = [a.name for a in at_rest] + [a.name for a in mem]

    # (label, at-rest adapter or None, semantic adapter or None)
    rows = [
        ("openfang(model,fixed)", OpenFangAdapter(strict_tip=True), None),
        ("langgraph-sqlite", LangGraphSqliteAdapter(), None),
        *([("langgraph-sqlite-store", None, lg_store)] if lg_store else []),
        *([letta_row] if letta_row else []),
        *([mem0_row] if mem0_row else []),
        *inspeximus_rows,
        ("naive-mem(scoped)", None,
         NaiveMemoryAdapter(enforce_user_scope=True)),
        ("naive-mem(unscoped)", None,
         NaiveMemoryAdapter(enforce_user_scope=False)),
    ]

    cells: dict[tuple[str, str], str] = {}
    checked_at: dict[str, str] = {}
    for label, ar_ad, sm_ad in rows:
        if ar_ad is not None:
            ar_ad.name = label
            point = getattr(ar_ad, "detection_point", "read")
            checked_at[label] = point
            for atk in at_rest:
                status = atk.run(ar_ad).status
                if status == "safe" and point == "audit":
                    status = "reported"
                cells[(label, atk.name)] = status
        else:
            for atk in at_rest:
                cells[(label, atk.name)] = "n/a"
        if sm_ad is not None:
            sm_ad.name = label
            for atk in mem:
                cells[(label, atk.name)] = atk.run(sm_ad).status
            close = getattr(sm_ad, "close", None)
            if callable(close):
                close()
        else:
            for atk in mem:
                cells[(label, atk.name)] = "n/a"

    short = {
        "tamper": "tamp", "truncate": "trunc", "delete_middle": "delMid",
        "reorder": "reord", "forge": "forge", "memory_injection": "inject",
        "cross_session_bleed": "bleed", "retrieval_hijack": "hijack",
        "indirect_prompt_injection": "promptInj",
    }
    cols = ["checkedAt"] + [short[n] for n in all_names]
    label_w = max(len(r[0]) for r in rows) + 1
    col_w = max(max(len(c) for c in cols), 10)

    def c(t): return t.center(col_w)
    head = " " * label_w + "| " + " | ".join(c(x) for x in cols)
    lines = [head, "-" * len(head)]
    for label, _, _ in rows:
        line = [label.ljust(label_w) + "|"]
        line += [c(checked_at.get(label, "n/a"))]
        line += [c(cells[(label, n)]) for n in all_names]
        lines.append(" ".join(line[:1]) + " " + " | ".join(line[1:]))
    return "\n".join(lines)


if __name__ == "__main__":
    print(full_scorecard())
