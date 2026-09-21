# Changelog

## Unreleased
- `retrieval_hijack` rebuilt so a relevance floor cannot pass it. The
  victim holds six genuine memories on one topic and the agent takes three;
  the attacker's single entry is stuffed with the topic's question words
  around an unrelated payload, so it is on topic by construction and can
  only appear by outranking a genuine memory. The earlier version padded
  toward a different topic, which any score floor kept out for free. The
  naive baseline now fails this cell at rank 1, as an undefended ranker
  should; earlier scorecards showed it as safe. Mem0's cell is re-measured
  in this release.
- CI actions moved to `actions/checkout@v5` and `actions/setup-python@v6`
  (the v4/v5 tags run on Node 20, which GitHub is retiring).
- Mem0 memory-specific adapter (`mem0_semantic.py`): real Mem0 driven
  through its own `add(infer=False)` and `search(filters, top_k)` paths on
  a private local Qdrant store, for the injection, bleed, hijack and
  indirect-prompt-injection attacks. The embedder is pluggable
  (`agmi/embedders.py`): the offline hashing embedder for plumbing and the
  bleed cell, all-MiniLM-L6-v2 via sentence-transformers (new `embedder`
  extra) for every cell that depends on ranking. Rows carry a
  `measured_on()` line naming the Mem0 version, embedder and which of
  Mem0's optional ranking signals were on.
- Recorded two facts about mem0ai 2.0.20's default read path that the row
  depends on: it drops candidates whose semantic score is under 0.1 before
  ranking, and its result count is `top_k` (a `limit=` argument is silently
  ignored and 20 returned).
- Shared Mem0 plumbing moved into `mem0_common.py`; the at-rest adapter
  now opens its store through it. Measured behaviour unchanged.
- pytest tiers: the default run stays offline; `pytest -m embedder` runs
  tests that need the cached model.
- inspeximus adapter (inspeximus 2.38.0, SQLite store with an opt-in signed
  receipt chain and a chain head kept in the user's config home), three rows:
  receipts off reads like LangGraph, five accepted; receipts on with the
  attacker holding the store's directory, five reported; receipts on with the
  attacker also holding the config home, four reported and a tail truncation
  accepted. Detection is the tool's audit call, not the read path.

## 0.5.0 (2026-09-14)
- License (MIT), authorship, file headers, contributing and security
  policy, CI workflow.
- README rewritten: headline table, threat model, measurement sequence,
  architecture diagrams, attack catalogue, per-target method, adapter guide.

## 0.4.0 (2026-09-14)
- Mem0 adapter (mem0ai 2.0.20, local Qdrant store, fully offline).
- All five at-rest attacks accepted silently on Mem0; history table and
  vector store left disagreeing after truncate.

## 0.3.0 (2026-09-14)
- Letta adapter (letta 0.16.8, core memory block checkpoint history).
- Embedded Postgres via pgserver so the Letta row runs without Docker.
- Fixed the truncate attack, which removed one entry instead of two on
  stores that address rows by position.

## 0.2.0 (2026-09-14)
- First real target: LangGraph SqliteSaver (langgraph-checkpoint-sqlite
  3.1.1). All five at-rest attacks accepted silently.
- Adapters now own payload mutation so blob-based stores can be attacked
  without corrupting their encoding.

## 0.1.0
- Attack catalogue, adapter interface, Python model of the OpenFang audit
  chain, naive memory reference target.
