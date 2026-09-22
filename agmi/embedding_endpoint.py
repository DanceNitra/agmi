# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""A local, OpenAI-compatible embeddings endpoint serving one of agmi's
embedders, for tools that only embed through a network API.

Letta is the case in hand: every one of its embedding providers is a remote
service (OpenAI, Ollama, a TEI server and so on), with no in-process
option. Pointing its ``openai`` provider at this endpoint keeps the
measurement offline and lets the same embedder be used across tools, so a
rank on the Letta row means the same thing as a rank on the Mem0 row.

The server binds to 127.0.0.1 on a free port, answers ``POST /v1/embeddings``
in the OpenAI response shape, and runs on a daemon thread. Nothing else is
served.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from agmi.embedders import Embedder


class LocalEmbeddingEndpoint:
    """``with LocalEmbeddingEndpoint(embedder) as ep: ep.base_url``."""

    def __init__(self, embedder: Embedder):
        self.embedder = embedder
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("endpoint is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1"

    def start(self) -> "LocalEmbeddingEndpoint":
        embedder = self.embedder

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):  # keep the test output quiet
                pass

            def do_POST(self):
                if not self.path.endswith("/embeddings"):
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                inputs = body.get("input", [])
                if isinstance(inputs, str):
                    inputs = [inputs]
                data = [{"object": "embedding", "index": i,
                         "embedding": embedder.embed(text, "add")}
                        for i, text in enumerate(inputs)]
                out = json.dumps({
                    "object": "list", "data": data,
                    "model": body.get("model", embedder.name),
                    "usage": {"prompt_tokens": 0, "total_tokens": 0},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    def __enter__(self) -> "LocalEmbeddingEndpoint":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
