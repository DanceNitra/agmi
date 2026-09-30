"""Case C (head deletion) against the expected_checkpoint_id anchor proposed in
langgraph#9099 (Dante-dan@8777ebb). SqliteSaver + EncryptedSerializer, sync path.
Part of the agmi experiments: github.com/tech4biz-yasha/agmi
"""
import sqlite3, tempfile, importlib.metadata as md
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.serde.encrypted import EncryptedSerializer

KEY = b"0123456789abcdef0123456789abcdef"

class S(TypedDict):
    approved: bool

def node(s):
    return {"approved": s["approved"]}

def open_(path):
    c = sqlite3.connect(path, check_same_thread=False)
    sv = SqliteSaver(c, serde=EncryptedSerializer.from_pycryptodome_aes(key=KEY))
    g = StateGraph(S); g.add_node("n", node); g.add_edge(START, "n"); g.add_edge("n", END)
    return c, g.compile(checkpointer=sv)

def seed():
    p = tempfile.mktemp(suffix=".db"); c, g = open_(p); cfg = {"configurable": {"thread_id": "t"}}
    g.invoke({"approved": False}, cfg); h1 = g.get_state(cfg).config["configurable"]["checkpoint_id"]
    g.invoke({"approved": True}, cfg); h2 = g.get_state(cfg).config["configurable"]["checkpoint_id"]
    c.close(); return p, h1, h2

def read(p, cfg):
    c, g = open_(p)
    try:
        return "served " + str(g.get_state(cfg).values)
    except Exception as e:
        return "RAISED " + type(e).__name__ + (": " + str(e)[:40] if type(e).__name__ == "ValueError" else "")

def cut(p, h1):
    c = sqlite3.connect(p)
    c.execute("delete from checkpoints where thread_id='t' and checkpoint_id>?", (h1,))
    c.execute("delete from writes where thread_id='t' and checkpoint_id>?", (h1,))
    c.commit(); c.close()

def anchored(h, **kw):
    return {"configurable": {"thread_id": "t", "expected_checkpoint_id": h, **kw}}

print("langgraph-checkpoint", md.version("langgraph-checkpoint"),
      "| langgraph-checkpoint-sqlite", md.version("langgraph-checkpoint-sqlite"))
import langgraph.checkpoint.sqlite.utils as u
print("anchor support present:", hasattr(u, "check_checkpoint_head"))

p, h1, h2 = seed()
print("1 C1 no edit, anchor         :", read(p, anchored(h2)))
p, h1, h2 = seed(); cut(p, h1)
print("2 C head deleted, no anchor  :", read(p, {"configurable": {"thread_id": "t"}}))
p, h1, h2 = seed(); cut(p, h1)
print("3 C head deleted, anchor     :", read(p, anchored(h2)))
p, h1, h2 = seed(); cut(p, h1)
print("4 historical read, anchor    :", read(p, anchored(h2, checkpoint_id=h1)))
p, h1, h2 = seed(); c, g = open_(p)
g.invoke({"approved": False}, anchored(h2))
nh = g.get_state({"configurable": {"thread_id": "t"}}).config["configurable"]["checkpoint_id"]; c.close()
print("5 genuine write, old anchor  :", read(p, anchored(h2)))
print("6 genuine write, new anchor  :", read(p, anchored(nh)))
p, h1, h2 = seed(); cut(p, h1); c, g = open_(p)
try:
    n = len(list(g.get_state_history(anchored(h2)))); print("7 history after deletion     : served", n, "states")
except Exception as e:
    print("7 history after deletion     : RAISED", type(e).__name__)
p, h1, h2 = seed(); c = sqlite3.connect(p)
old = c.execute("select type,checkpoint from checkpoints where thread_id='t' and checkpoint_id=?", (h1,)).fetchone()
c.execute("update checkpoints set type=?,checkpoint=? where thread_id='t' and checkpoint_id=?", (old[0], old[1], h2))
c.commit(); c.close()
print("8 head overwritten, id kept  :", read(p, anchored(h2)))

# ---- async path (AsyncSqliteSaver), same head deletion ----
import asyncio, aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

async def _agraph(path):
    conn = await aiosqlite.connect(path)
    sv = AsyncSqliteSaver(conn, serde=EncryptedSerializer.from_pycryptodome_aes(key=KEY))
    g = StateGraph(S); g.add_node("n", node); g.add_edge(START, "n"); g.add_edge("n", END)
    return conn, g.compile(checkpointer=sv)

async def _async_case_c():
    p = tempfile.mktemp(suffix=".db"); conn, g = await _agraph(p); cfg = {"configurable": {"thread_id": "t"}}
    await g.ainvoke({"approved": False}, cfg); h1 = (await g.aget_state(cfg)).config["configurable"]["checkpoint_id"]
    await g.ainvoke({"approved": True}, cfg); h2 = (await g.aget_state(cfg)).config["configurable"]["checkpoint_id"]
    await conn.close(); cut(p, h1); conn, g = await _agraph(p)
    print("9 async, head deleted, no anchor:", "served", (await g.aget_state(cfg)).values)
    try:
        print("10 async, head deleted, anchor  :", "served", (await g.aget_state(anchored(h2))).values)
    except Exception as e:
        print("10 async, head deleted, anchor  : RAISED", type(e).__name__)
    await conn.close()

asyncio.run(_async_case_c())
