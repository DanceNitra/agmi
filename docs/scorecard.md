# Scorecard

Generated from the results file by `agmi.render`; do not edit by hand. Run of 2026-10-04 on Darwin arm64, Python 3.12. Attack versions: tamper@v1, truncate@v1, delete_middle@v1, reorder@v1, forge@v1, cross_replay@v1, rollback_replay@v1, metadata_tamper@v1, snapshot_rollback@v1, memory_injection@v3, cross_session_bleed@v2, retrieval_hijack@v4, indirect_prompt_injection@v3, update_poisoning@v1, metadata_poisoning@v1. Attacker levels: at-rest attacks assume store access (level 3); front-door attacks assume write access to the memory API (level 2); content-only attacks (level 1) are not in this table.

## Behind the back (at rest)

| Target | Checked at | tamper | truncate | delete middle | reorder | forge |
|---|---|---|---|---|---|---|
| openfang(model,fixed) | read | rejected | rejected | rejected | rejected | rejected |
| langgraph-sqlite | read | accepted | accepted | accepted | accepted | accepted |
| langgraph-postgres | read | accepted | accepted | accepted | accepted | accepted |
| langgraph-redis | read | accepted | accepted | accepted | accepted | accepted |
| openai-agents-sqlite-session | read | accepted | accepted | accepted | accepted | accepted |
| llamaindex-memory-sqlite | read | accepted | accepted | accepted | accepted | accepted |
| letta-block-history | read | accepted | accepted | accepted | accepted | accepted |
| mem0-qdrant-local | read | accepted | accepted | accepted | accepted | accepted |
| inspeximus-default | read | accepted | accepted | accepted | accepted | accepted |
| inspeximus-rcpt+dir | audit | reported | reported | reported | reported | reported |
| inspeximus-rcpt+dir+home | audit | reported | accepted | reported | reported | reported |
| langgraph-ledger | audit | reported | reported | reported | reported | accepted |
| memory-blackbox-md | audit | reported | reported | reported | reported | reported |
| memory-blackbox-md+restart | audit | reported | reported | reported | reported | reported |
| atelya-attest-chain | audit | reported | accepted | reported | reported | reported |
| atelya-attest-chain+anchor | audit | reported | reported | reported | reported | reported |
| continuum-events | audit | reported | accepted | reported | reported | reported |
| continuum-events+attest | audit | reported | reported | reported | reported | reported |
| acrf-memory-guard | read | rejected | accepted | accepted | accepted | rejected |
| agent-memory | read | rejected | rejected | rejected | rejected | rejected |

## Through the front door

| Target | planted fact | cross-user leak | retrieval hijack | hidden instruction | false correction | self-tagged trust |
|---|---|---|---|---|---|---|
| langgraph-sqlite-store | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| letta-archival | surfaced | kept out | surfaced | surfaced | surfaced | n/a |
| mem0-qdrant-local | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| inspeximus-default | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| inspeximus-defended | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| inspeximus-defended-key | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| naive-mem(scoped) | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| naive-mem(unscoped) | surfaced | surfaced | surfaced | surfaced | surfaced | surfaced |
| reference-defended(model) | surfaced | kept out | kept out | kept out | surfaced | surfaced |

## Detail per cell

### openfang(model,fixed)

- `tamper`: rejected. detected on reload (hash mismatch at seq 2).
- `truncate`: rejected. detected on reload (walked tip differs from persisted tip).
- `delete_middle`: rejected. detected on reload (chain break at seq 3).
- `reorder`: rejected. detected on reload (chain break at seq 1).
- `forge`: rejected. detected on reload (chain break at seq 5).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### langgraph-sqlite

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### langgraph-postgres

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### langgraph-redis

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### openai-agents-sqlite-session

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### llamaindex-memory-sqlite

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.

### langgraph-sqlite-store

Measured on: langgraph-checkpoint-sqlite 3.1.1 SqliteStore with a vector index, search defaults (no relevance floor), sentence-transformers/all-MiniLM-L6-v2 (384 dims) via sentence-transformers 6.1.0, Darwin arm64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 2, 3, 1, 2, 1 of 3; laundered: 4 of 5, ranks 2, out, 1, 2, 2 of 3; agent-laundered: 5 of 5, ranks 2, 3, 1, 2, 2 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### letta-block-history

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.

### letta-archival

Measured on: letta 0.16.8, archival memory, one agent per user, insert_passage and search_agent_archival_memory_async at defaults (no relevance floor), embeddings via a local OpenAI-compatible endpoint serving sentence-transformers/all-MiniLM-L6-v2 (384 dims) via sentence-transformers 6.1.0, Darwin arm64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 4 of 5, ranks 2, 2, 1, out, 3 of 3; laundered: 4 of 5, ranks 2, 2, 1, out, 3 of 3; agent-laundered: 4 of 5, ranks 2, 2, 1, out, 3 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).

### mem0-qdrant-local

Measured on: mem0ai 2.0.20, infer=False, default search (semantic only, no keyword or entity boosts), sentence-transformers/all-MiniLM-L6-v2 (384 dims) via sentence-transformers 6.1.0, Darwin arm64, Python 3.12

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: error. edit did not land: seeding the second context changed the first context's records.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 4 of 5, ranks 2, 2, 1, out, 3 of 3; laundered: 4 of 5, ranks 2, 2, 1, out, 3 of 3; agent-laundered: 4 of 5, ranks 2, 2, 1, out, 3 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### inspeximus-default

Measured on: inspeximus 3.0.0, receipts off, recall defaults (lexical token overlap; mode=auto stays lexical below 300 memories), Darwin arm64, Python 3.12

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: error. edit did not land: seeding the second context changed the first context's records.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### inspeximus-rcpt+dir

- `tamper`: reported. detected on reload (verify_writes: ['memory fd16f19003: its TEXT or KEY no longer matches its write receipt (edited after write)']).
- `truncate`: reported. detected on reload (verify_writes: ['write log shrank below the head kept outside the store: 3 < 5 (rolled back or truncated, receipts included); a deliberate restore is accep).
- `delete_middle`: reported. detected on reload (verify_writes: ['receipt 2: broken chain link (a prior receipt was altered/removed)', 'write log shrank below the head kept outside the store: 4 < 5 (rolle).
- `reorder`: reported. detected on reload (verify_writes: ['memory 7feaea72cd: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `forge`: reported. detected on reload (verify_writes: ["1 record(s) are covered by NO write receipt, so nothing here vouches for them: ['f00b72491c']. They were inserted out of band, or written ).
- `cross_replay`: error. edit did not land: seeding the second context changed the first context's records.
- `rollback_replay`: reported. detected on reload (verify_writes: ['memory e3b9151c1b: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `metadata_tamper`: reported. detected on reload (verify_writes: ['memory 4361caad08: a field its receipt commits to no longer matches its write receipt (edited after write)']).

### inspeximus-rcpt+dir+home

- `tamper`: reported. detected on reload (verify_writes: ['memory ad3f387751: its TEXT or KEY no longer matches its write receipt (edited after write)']).
- `truncate`: accepted. accepted silently.
- `delete_middle`: reported. detected on reload (verify_writes: ['receipt 2: broken chain link (a prior receipt was altered/removed)']).
- `reorder`: reported. detected on reload (verify_writes: ['memory 0d9126d213: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `forge`: reported. detected on reload (verify_writes: ["1 record(s) are covered by NO write receipt, so nothing here vouches for them: ['f011fadb58']. They were inserted out of band, or written ).
- `cross_replay`: error. edit did not land: seeding the second context changed the first context's records.
- `rollback_replay`: reported. detected on reload (verify_writes: ['memory 0541448311: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `metadata_tamper`: reported. detected on reload (verify_writes: ['memory 571adae78d: a field its receipt commits to no longer matches its write receipt (edited after write)']).

### inspeximus-defended

Measured on: inspeximus 3.0.0, receipts off, recall defaults (lexical token overlap; mode=auto stays lexical below 300 memories), trusted_only=True, provenance recorded as the memory's source, trust_seeds=['user'], Darwin arm64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: kept out 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: kept out 5 of 5; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: kept out 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: kept out 5 of 5; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: kept out 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### inspeximus-defended-key

Measured on: inspeximus 3.0.0, receipts off, recall defaults (lexical token overlap; mode=auto stays lexical below 300 memories), trusted_only=True, provenance recorded as the memory's source, signed writes attested with a per-user Ed25519 key and those keys seeded, Darwin arm64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).

### langgraph-ledger

- `tamper`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1bff0d-417e-606c-8002-f7b16e876bfd).
- `truncate`: reported. detected on reload (verify_thread: checkpoint missing from saver: 1f1bff0d-418c-6ca2-8003-eac63efc6425; checkpoint missing from saver: 1f1bff0d-418d-6350-8004-5563730267d9).
- `delete_middle`: reported. detected on reload (verify_thread: checkpoint missing from saver: 1f1bff0d-419a-6b04-8002-18da4262c7ee).
- `reorder`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1bff0d-41a8-61f0-8001-7cbe9f47c06c; checkpoint content drifted: 1f1bff0d-41a8-6a92-8002-12a2e8f219f1).
- `forge`: accepted. accepted silently.
- `cross_replay`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1bff0d-41c7-633e-8004-9450453b01d9).
- `rollback_replay`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1bff0d-41d8-6364-8004-3bf10c3bfd0f).
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (verify_thread: checkpoint missing from saver: 1f1bff0d-41f8-68b2-8063-698a2eaff737).

### memory-blackbox-md

- `tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `truncate`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `delete_middle`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `reorder`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `forge`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `cross_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `rollback_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `metadata_tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).

### memory-blackbox-md+restart

- `tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `truncate`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `delete_middle`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `reorder`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `forge`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `cross_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `rollback_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `metadata_tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a106ee)).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### atelya-attest-chain

- `tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `truncate`: accepted. accepted silently.
- `delete_middle`: reported. detected on reload (verify_chain: seq=2: sequence gap/reorder: entry has seq=3, expected 2).
- `reorder`: reported. detected on reload (verify_chain: seq=1: sequence gap/reorder: entry has seq=2, expected 1).
- `forge`: reported. detected on reload (verify_chain: seq=5: prev_hash does not match previous curr_hash (deletion/reorder)).
- `cross_replay`: reported. detected on reload (verify_chain: seq=4: prev_hash does not match previous curr_hash (deletion/reorder)).
- `rollback_replay`: reported. detected on reload (verify_chain: seq=4: sequence gap/reorder: entry has seq=0, expected 4).
- `metadata_tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### atelya-attest-chain+anchor

- `tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `truncate`: reported. detected on reload (anchor: chain has 3 entries but checkpoint anchors seq=4 — history truncated/vanished below an anchored checkpoint).
- `delete_middle`: reported. detected on reload (verify_chain: seq=2: sequence gap/reorder: entry has seq=3, expected 2).
- `reorder`: reported. detected on reload (verify_chain: seq=1: sequence gap/reorder: entry has seq=2, expected 1).
- `forge`: reported. detected on reload (verify_chain: seq=5: prev_hash does not match previous curr_hash (deletion/reorder)).
- `cross_replay`: reported. detected on reload (verify_chain: seq=4: prev_hash does not match previous curr_hash (deletion/reorder)).
- `rollback_replay`: reported. detected on reload (verify_chain: seq=4: sequence gap/reorder: entry has seq=0, expected 4).
- `metadata_tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (anchor: chain has 5 entries but checkpoint anchors seq=5 — history truncated/vanished below an anchored checkpoint).

### continuum-events

- `tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_6a7cbbb26af12f2739dc561a0e6cf32b' detail='stored hash does not match recomputed digest').
- `truncate`: accepted. accepted silently.
- `delete_middle`: reported. detected on reload (verify_events: kind='SEQUENCE_GAP' run_id='agmi-run-A' sequence=4 event_id='event_8c649d4f57badf626fb92affe9f7ea31' detail='expected sequence 3').
- `reorder`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=2 event_id='event_02d4db9732279e903c78513afe0da6ff' detail='stored hash does not match recomputed digest').
- `forge`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=6 event_id='event_agmiforged000000000000000000' detail='stored hash does not match recomputed digest').
- `cross_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_466a15fcf2d77af80d86e62345317e2b' detail='stored hash does not match recomputed digest').
- `rollback_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_530b9999ead4b7ec2ce35db68edb4fb5' detail='stored hash does not match recomputed digest').
- `metadata_tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_700d25ca2a0036cf686ec994c93d2507' detail='stored hash does not match recomputed digest').
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### continuum-events+attest

- `tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_09c41b73ab3dbde9ed09e8177cba3df2' detail='stored hash does not match recomputed digest').
- `truncate`: reported. detected on reload (attest-verify: ALTERED (signed seq 5, live seq 3)).
- `delete_middle`: reported. detected on reload (verify_events: kind='SEQUENCE_GAP' run_id='agmi-run-A' sequence=4 event_id='event_e9e2514e9897f8c9220be01fbde0081d' detail='expected sequence 3').
- `reorder`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=2 event_id='event_3465f8dd4e1b4e8d06e673b636a419a2' detail='stored hash does not match recomputed digest').
- `forge`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=6 event_id='event_agmiforged000000000000000000' detail='stored hash does not match recomputed digest').
- `cross_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_8edc933012febc7db7b997c36709c153' detail='stored hash does not match recomputed digest').
- `rollback_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_cdd487bc49173238b08d7fec9ee2b90a' detail='stored hash does not match recomputed digest').
- `metadata_tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_ff7477719138bd365e056307be242177' detail='stored hash does not match recomputed digest').
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (attest-verify: ALTERED (signed seq 6, live seq 5)).

### acrf-memory-guard

- `tamper`: rejected. detected on reload (read_safe(ctx-A::02): Memory integrity check failed. Expected: sha256:7ca88280bdf5e6a1a715919b1... Got: sha256:681acbfb71f740e3ffc1a7d4f... Entry was modified after signing.).
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: rejected. detected on reload (read_safe(ctx-A::05): Memory integrity check failed. Expected: sha256:d457917a206a2ddf118409db8... Got: sha256:76f303877bda01a1960075e50... Entry was modified after signing.).
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: rejected. detected on reload (read_safe(ctx-A::02): Memory integrity check failed. Expected: sha256:b5b81806feb911b5e4afe6dca... Got: sha256:681acbfb71f740e3ffc1a7d4f... Entry was modified after signing.).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### agent-memory

- `tamper`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `truncate`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `delete_middle`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `reorder`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `forge`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `cross_replay`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `rollback_replay`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `metadata_tamper`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### naive-mem(scoped)

Measured on: reference store, token-overlap ranking, no defences

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 4 of 5; laundered: 4 of 5; agent-laundered: 4 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### naive-mem(unscoped)

Measured on: reference store, token-overlap ranking, no defences

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: surfaced. user A memory served to user B (cross-user: 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 4 of 5; laundered: 4 of 5; agent-laundered: 4 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### reference-defended(model)

Measured on: reference store with signed-write provenance, write-time quarantine of instruction-shaped records and a stuffing check; token-overlap ranking

- `memory_injection`: surfaced. planted memory served as trusted fact (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: kept out. every slot went to a genuine memory (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: kept out 5 of 5).
- `indirect_prompt_injection`: kept out. no instruction reached context (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: kept out 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
