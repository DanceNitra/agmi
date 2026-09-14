Repo: https://github.com/letta-ai/letta/issues/new
Title: Block checkpoint history can be rewritten in the database without undo, redo or checkpoint noticing; measured with a reproducible suite

Summary

In letta 0.16.8 the core memory checkpoint history (`block_history`, plus `block.current_history_entry_id`) accepts direct edits in Postgres silently. I measured this with a small open source conformance suite, agmi, that seeds a block through `BlockManager.create_or_update_block_async`, `update_block_async` and `checkpoint_block_async`, edits the rows directly, then walks `undo_checkpoint_block` back to the first checkpoint and `redo_checkpoint_block` forward again.

Results

| edit made to the store | what Letta does afterwards |
|---|---|
| change the `value` of a middle checkpoint | undo lands on the changed value, no error |
| delete the newest two checkpoints and repoint the block | the agent's core memory rewinds two checkpoints, every call succeeds |
| delete one checkpoint from the middle | undo and redo skip the hole, no error |
| swap the `value` of two checkpoints | loads and walks fine, no error |
| insert a new checkpoint after the tip and repoint the block | the agent's core memory is now the inserted text, no error |

Reproduce

```
git clone https://github.com/tech4biz-yasha/agmi && cd agmi
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,letta]"
PYTHONPATH=. python3 -m pytest tests/test_letta_block_history.py -q
```

The adapter is `agmi/adapters/letta_block_history.py`. It starts an embedded Postgres through `pgserver` so nothing else is needed; set `LETTA_PG_URI` to use your own. The test pins the version.

Why I am raising it

The undo and redo code says explicitly that it tolerates pruned sequence numbers, so the gap tolerance is deliberate and I am not calling it a bug. The reason I think it deserves a look is that the feature is presented as a checkpoint history with undo and redo, and users will reasonably read that as a record of what the agent's memory was. Today it is a record only as long as nobody with database access edits it. For agents whose memory matters to a regulator or an audit, that is a meaningful difference.

Two questions

1. Would an optional integrity check on `block_history` be acceptable? A per row hash over (`block_id`, `sequence_number`, `value`, previous row hash) verified on undo, redo and checkpoint would make every edit above visible. Off by default.
2. Is there an existing place in the Letta roadmap for tamper evidence on agent state, so I can align rather than propose in isolation?

Happy to open a PR if the direction is welcome.

Yasha Khandelwal
