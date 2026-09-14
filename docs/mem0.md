Repo: https://github.com/mem0ai/mem0/issues/new
Title: History table and payload hash are never checked against the vector store; store edits are invisible to get_all, search and history. Measured with a reproducible suite

Summary

In mem0ai 2.0.20 with the default local Qdrant store, memories edited directly on disk are returned by `get_all()`, `search()` and `history()` with no indication that anything changed. Mem0 already keeps two things that could detect this, an ADD/UPDATE/DELETE event per memory in the history table and an md5 `hash` in each point's payload, but neither is ever compared against what the vector store actually holds.

I measured this with a small open source conformance suite, agmi, that seeds through `Memory.add(infer=False)` with an offline embedder, edits the Qdrant `points` table directly, reopens, and reads through Mem0's own API.

Results

| edit made to the store | what Mem0 does afterwards |
|---|---|
| change the `data` of one point (payload `hash` left stale) | returned as is, no error |
| delete the newest two points | history still lists five memories, get_all returns three, no error |
| delete one point from the middle | same, no error |
| swap the `data` of two points | returned as is, no error |
| insert a new point copied from the tip with new text | returned as a real memory, no error |

Reproduce

```
git clone https://github.com/tech4biz-yasha/agmi && cd agmi
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mem0]"
PYTHONPATH=. python3 -m pytest tests/test_mem0_at_rest.py -q
```

Fully offline, no API key. The adapter is `agmi/adapters/mem0_at_rest.py`. The test pins the version.

Why I am raising it

This is a design gap, not a bug, and I am not claiming otherwise. The reason it stands out for Mem0 specifically is that the pieces for a check already exist. The history table looks like an audit log and the payload hash looks like an integrity hash, and a user reading the code would assume they are used that way. Today the hash is only used for de-duplication and the history is write only.

Two questions

1. Would you accept an optional `verify()` (or a flag on `get_all` and `search`) that recomputes the payload hash and reconciles the vector store against the history table, reporting any memory that was changed, removed or added out of band? Off by default.
2. A related note, not a finding: the FAISS store now uses a restricted unpickler, which is good, but the local Qdrant path still round trips full `PointStruct` objects through pickle. If that is on your radar already I will leave it; if not, I can open it separately as a private report first.

Happy to open a PR for question 1 if the direction is welcome.

Yasha Khandelwal
