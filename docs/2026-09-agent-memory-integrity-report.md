# Agent Memory Integrity Report, September 2026

Yasha Khandelwal, 14 September 2026. First report in a monthly series. Suite and raw results: https://github.com/tech4biz-yasha/agmi

## The finding

I took three of the most used agent memory layers, stored five memories in each through its normal API, edited the memory behind its back, and asked it to read its memory again. None of them noticed.

| Target | Version | tamper | truncate | delete_middle | reorder | forge |
|---|---|:-:|:-:|:-:|:-:|:-:|
| LangGraph `SqliteSaver` | langgraph-checkpoint-sqlite 3.1.1 | accepted | accepted | accepted | accepted | accepted |
| Letta core memory checkpoint history | letta 0.16.8 | accepted | accepted | accepted | accepted | accepted |
| Mem0 local Qdrant store | mem0ai 2.0.20 | accepted | accepted | accepted | accepted | accepted |

"Accepted" means the library loaded the altered store, raised nothing, and the agent carried on from the altered memory as if it were true. In every forge case the agent's next action starts from text an attacker wrote.

## What this is and is not

It is not three vulnerabilities. None of these libraries claims its store is tamper evident, and each trusts its database the way any application trusts its disk. If you can write to the SQLite file you already own the machine, and a maintainer is right to say so.

It is one measurement that had not been made: with one yardstick, across tools, the answer to "can this memory layer tell that its memory was changed?" is no, everywhere. That matters in exactly the places agent memory is starting to be used as a record:

- when the memory is the audit trail, in finance, healthcare or anything with a regulator behind it;
- when the store is shared, a Postgres several services use, a mounted volume, a multi tenant host;
- when an agent's past decisions are replayed to justify its next one;
- when a backup job, migration script or lower privileged service can write where the agent reads.

In those deployments "the store loaded fine" and "the store is what was written" are different questions. Today only the first one gets answered.

## Where the gap is a mismatch, not just a design choice

Two of the three go a step further than "no check".

Letta presents this feature as a checkpoint history with undo and redo. Its undo and redo code deliberately tolerates missing sequence numbers. So a history with entries deleted from the middle or the end walks cleanly, and after two checkpoints are removed the agent's core memory silently rewinds while every call keeps succeeding. A history that can be rewritten without trace is a record only until someone edits it.

Mem0 already stores the two things that would catch this. Every memory gets an ADD, UPDATE or DELETE event in a history table, and every stored point carries an md5 of its text. Neither is ever checked. The hash is used for de-duplication, and the history is write only. After two memories are removed from the store, `history()` still lists five and `get_all()` returns three, and nothing reconciles the two.

LangGraph is the plainest case. The checkpointer has no integrity logic at all, so the only thing that can fail on reload is deserialization. A tamper that keeps the msgpack valid is invisible by construction.

## How the measurement works

Every cell comes from the same four steps, and the library's own API is on both sides of the tampering so the result is the library's answer, not mine.

1. Seed five entries through the library's normal write path.
2. Edit the backing store directly: SQL against the table, or bytes inside the blob.
3. Reopen the store the way a restart would.
4. Read through the library's normal read path and record whether it raised, refused or reported anything.

"Detected" is counted only when the library itself complains. I never infer detection from content coming back different. Each target has a test that asserts the measured result at the measured version, so the day a maintainer adds a check the test fails and the table gets updated with the new version. A weekly CI run repeats this against the latest release.

Five edits are made per target: change one entry, delete the newest two, delete one from the middle, swap two, and insert a fabricated entry that looks authentic. The precise rule for each is in the repo README.

## What a fix costs

Not much, which is the point of publishing this rather than filing it as a complaint. A hash chain in checkpoint or history metadata, each entry hashing its own content plus the previous entry's hash, verified on read when a flag is on, catches all five edits above. Off by default it costs nothing for anyone who does not turn it on. For Mem0 the pieces already exist and only need to be compared. I have opened one issue per project proposing exactly that and offering the PR.

## What is not in this report

The semantic side of memory, whether attacker content reaches the agent's context or crosses a user boundary, is not measured against real tools yet. The suite has those attacks but only against a reference baseline, and running them honestly needs real embedders. That is the October report.

Deserialization is also not in here. Both LangGraph and Mem0 still unpickle from their stores in some paths, and one of them has patched a version of that before. Anything found there goes to the maintainers privately first.

## Reproduce it

```
git clone https://github.com/tech4biz-yasha/agmi && cd agmi
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langgraph,letta,mem0]"
PYTHONPATH=. python3 agmi/full_runner.py 2>/dev/null | grep "|"
```

Offline, no API keys, no Docker, under a minute. If your memory layer is not in the table and you want it measured, an adapter is one file; the contributing guide explains the five rules that keep a row honest.
