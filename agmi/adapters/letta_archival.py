# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for Letta's archival memory, memory-specific attack surface.

Letta has two memories. Core memory (the blocks an agent edits, measured at
rest in ``letta_block_history``) does not search. Archival memory is the
long-term store an agent writes facts into with ``archival_memory_insert``
and searches by meaning with ``archival_memory_search``; that is the
surface for the memory-specific attacks, so this is a separate row.

Write path
    ``PassageManager.insert_passage(agent_state, text, actor)``, what the
    ``archival_memory_insert`` tool calls. The text is stored as given and
    embedded through the agent's embedding configuration.

Read path
    ``AgentManager.search_agent_archival_memory_async(agent_id, query,
    top_k)``, what the ``archival_memory_search`` tool calls, with every
    other parameter at its default. Results are passed to the attack
    exactly as Letta returns them: no client-side filtering and no floor
    of this suite's own. Letta returns no score with a hit, so ``score``
    is 0.0 on every ``Retrieved``; rank order is Letta's.

    Two facts about letta 0.16.8 decide the row. Its archival search
    applies no relevance floor: a memory sharing nothing with the query
    still comes back. And archives are per agent: a query through one
    agent never sees another agent's passages, so isolation holds by
    construction. This adapter models one user as one agent, which is how
    Letta is deployed for separate users.

Embedder
    Letta only embeds through a network provider, so this adapter starts a
    local OpenAI-compatible endpoint (``agmi.embedding_endpoint``) serving
    the chosen agmi embedder and points Letta's ``openai`` embedding
    provider at it. Nothing about Letta's storage or search is replaced;
    only where the vectors come from. Cells that depend on ranking are
    published only when measured with a real sentence embedder.

Store
    The same embedded Postgres the at-rest adapter uses (``pgserver``, or
    ``LETTA_PG_URI``). ``reset()`` starts a new generation of agents rather
    than dropping the schema each time, since archives are per agent and a
    fresh agent has an empty archive; the schema is dropped on ``close()``.
"""

from __future__ import annotations

import asyncio
import importlib.metadata as md
import logging
import os
import platform
import sys

from agmi.adapters.semantic_base import (
    MemoryItem, Retrieved, SemanticMemoryAdapter,
)
from agmi.embedders import Embedder, HashEmbedder
from agmi.embedding_endpoint import LocalEmbeddingEndpoint

#: Row label as it appears on the scorecard. The runner may override it.
LABEL = "letta-archival"


def _quiet_letta() -> None:
    """Letta logs every embedding call at INFO through loggers it creates
    with an explicit level, so the level has to be set on each of them
    after they exist. Keeps agmi's own output readable."""
    for name in list(logging.root.manager.loggerDict):
        if name.startswith(("Letta", "letta", "httpx", "pgserver")):
            logging.getLogger(name).setLevel(logging.WARNING)


def letta_version() -> str:
    try:
        return md.version("letta")
    except md.PackageNotFoundError:
        return "not installed"


class LettaArchivalAdapter(SemanticMemoryAdapter):
    """Real Letta archival memory, one agent per user, for the
    memory-specific attacks.

    Parameters
    ----------
    embedder:
        Served to Letta through the local endpoint. Defaults to the offline
        hashing embedder; pass ``SentenceTransformerEmbedder()`` for a
        measurement that can be published for every cell.
    label:
        Scorecard row name. Defaults to ``LABEL``.
    """

    def __init__(self, embedder: Embedder | None = None,
                 label: str | None = None):
        self.embedder: Embedder = embedder or HashEmbedder()
        self.name = label or LABEL
        self._endpoint: LocalEmbeddingEndpoint | None = None
        self._actor = None
        self._agents: dict[str, object] = {}
        self._generation = 0
        self._open = False

    # --- lifecycle -----------------------------------------------------
    def _boot(self) -> None:
        """Start the endpoint, connect Letta to the embedded Postgres, and
        create the schema, organisation and actor. Once per adapter."""
        os.environ.setdefault("OPENAI_API_KEY", "sk-agmi-offline-dummy")
        # Importing the at-rest adapter sets LETTA_PG_URI before letta is
        # imported anywhere, which is the only order that works.
        from agmi.adapters.letta_block_history import _ensure_env
        try:
            _ensure_env()
        except NotImplementedError:
            raise
        try:
            import letta.orm  # noqa: F401  registers every table
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise NotImplementedError(
                "letta is not installed; run "
                "pip install 'agent-memory-integrity[letta]'") from exc
        from letta.orm.base import Base
        from letta.server.db import engine
        from sqlalchemy import text
        from letta.services.organization_manager import OrganizationManager
        from letta.services.user_manager import UserManager

        _quiet_letta()
        self._endpoint = LocalEmbeddingEndpoint(self.embedder).start()

        async def _init():
            async with engine.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                await conn.run_sync(Base.metadata.drop_all)
                await conn.run_sync(Base.metadata.create_all)
                # Letta's migrations give messages.sequence_id a sequence;
                # create_all does not, and agent creation writes a message.
                await conn.execute(text(
                    "CREATE SEQUENCE IF NOT EXISTS message_seq_id_seq"))
                await conn.execute(text(
                    "ALTER TABLE messages ALTER COLUMN sequence_id "
                    "SET DEFAULT nextval('message_seq_id_seq')"))
            org = await OrganizationManager().create_default_organization_async()
            return await UserManager().create_default_actor_async(org_id=org.id)

        self._actor = asyncio.run(_init())
        self._open = True

    def reset(self) -> None:
        """A new generation of agents: every user gets a fresh, empty
        archive on next use. Cheap, and isolation is per agent anyway."""
        if not self._open:
            self._boot()
        self._generation += 1
        self._agents = {}

    def close(self) -> None:
        """Drop the schema and stop the endpoint. Idempotent."""
        if self._open:
            try:
                from letta.orm.base import Base
                from letta.server.db import engine

                async def _drop():
                    async with engine.begin() as conn:
                        await conn.run_sync(Base.metadata.drop_all)
                asyncio.run(_drop())
            except Exception:  # noqa: BLE001 - best effort on teardown
                pass
            self._open = False
        if self._endpoint is not None:
            self._endpoint.stop()
            self._endpoint = None
        self._agents = {}

    def __enter__(self) -> "LettaArchivalAdapter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- one agent per user --------------------------------------------
    def _embedding_config(self):
        from letta.schemas.embedding_config import EmbeddingConfig
        return EmbeddingConfig(
            embedding_endpoint_type="openai",
            embedding_endpoint=self._endpoint.base_url,
            embedding_model=f"agmi-{self.embedder.name}",
            embedding_dim=self.embedder.dims,
            embedding_chunk_size=300,
        )

    def _agent(self, user_id: str):
        if not self._open:
            self.reset()
        state = self._agents.get(user_id)
        if state is not None:
            return state
        from letta.schemas.agent import CreateAgent
        from letta.schemas.block import CreateBlock
        from letta.schemas.llm_config import LLMConfig
        from letta.services.agent_manager import AgentManager

        create = CreateAgent(
            name=f"{user_id}-g{self._generation}",
            llm_config=LLMConfig.default_config("gpt-4o-mini"),  # never called
            embedding_config=self._embedding_config(),
            memory_blocks=[CreateBlock(label="human", value="")],
            include_base_tools=False,
        )
        state = asyncio.run(AgentManager().create_agent_async(create, actor=self._actor))
        _quiet_letta()
        self._agents[user_id] = state
        return state

    # --- the tool's own write and read paths ---------------------------
    def add_memory(self, item: MemoryItem) -> None:
        from letta.services.passage_manager import PassageManager
        state = self._agent(item.user_id)
        tags = [f"source:{item.source}"]
        asyncio.run(PassageManager().insert_passage(state, item.text,
                                                    self._actor, tags=tags))

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        from letta.services.agent_manager import AgentManager
        state = self._agent(user_id)
        hits = asyncio.run(AgentManager().search_agent_archival_memory_async(
            agent_id=state.id, actor=self._actor, query=query, top_k=k))
        return [Retrieved(text=str(h.get("content", "")), user_id=user_id,
                          score=0.0) for h in hits or []]

    def supports_users(self) -> bool:
        return True

    # --- provenance for reports ----------------------------------------
    def measured_on(self) -> str:
        return (f"letta {letta_version()}, archival memory, one agent per user, "
                f"insert_passage and search_agent_archival_memory_async at "
                f"defaults (no relevance floor), embeddings via a local "
                f"OpenAI-compatible endpoint serving {self.embedder.describe()}, "
                f"{platform.system()} {platform.machine()}, "
                f"Python {sys.version_info.major}.{sys.version_info.minor}")
