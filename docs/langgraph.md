Repo: https://github.com/langchain-ai/langgraph/issues/new
Title: SqliteSaver has no tamper evidence on the checkpoint store; measured with a reproducible suite, would an optional integrity mode be welcome?

Summary

`langgraph-checkpoint-sqlite` 3.1.1 (with `langgraph-checkpoint` 4.2.0) loads a checkpoint store that has been edited directly in SQLite without any indication that it changed. I measured this with a small open source conformance suite, agmi, that seeds through `SqliteSaver.put()`, edits the `checkpoints` table behind the library's back, reopens, and reads through `get()` and `list()`.

Results

| edit made to the store | what SqliteSaver does on reload |
|---|---|
| change one checkpoint's channel value inside the msgpack blob | loads it, no error |
| delete the newest two checkpoints | resumes from the older tip, no error |
| delete one checkpoint from the middle | loads, parent link now dangles, no error |
| swap the content of two checkpoints | loads, no error |
| insert a fabricated checkpoint after the tip with a later UUID and valid parent | resumes from the fabricated one, no error |

Reproduce

```
git clone https://github.com/tech4biz-yasha/agmi && cd agmi
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langgraph]"
PYTHONPATH=. python3 -m pytest tests/test_langgraph_sqlite.py -q
```

The adapter is `agmi/adapters/langgraph_sqlite.py`. The test pins the version, so it will fail the day this changes.

Why I am raising it

I understand this is by design. The checkpointer trusts its store the way any database trusts its disk, and nothing in the docs claims otherwise. I am raising it because LangGraph checkpoints are increasingly used as the record of what an agent did, in places where the SQLite file or Postgres rows are reachable by more than the agent process (shared volumes, multi tenant hosts, backup and migration jobs). In those deployments "the store loaded fine" and "the store is what was written" are different questions, and only the first one is answered today.

Two questions

1. Would an optional integrity mode be acceptable upstream? The cheapest version is a hash chain: each checkpoint's metadata carries a hash over its own content plus the parent's hash, and `get()` and `list()` verify the chain when the mode is on. Off by default, zero cost for anyone who does not turn it on.
2. If yes, would you prefer it in the serializer layer (so every checkpointer gets it) or per checkpointer? I am happy to open a PR either way.

Yasha Khandelwal
