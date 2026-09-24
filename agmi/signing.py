# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Signed writes: provenance bound by a key rather than a label.

A ``source`` label is text, and whoever writes the memory writes the label.
A signature is different: it can only be produced by whoever holds the
writer's key. The attacks use this to separate three attacker positions.

- An attacker with write access to the memory API but no key can write any
  label they like and still cannot produce a valid signature. A store that
  verifies signatures keeps their writes out of trusted retrieval.
- Content that entered through the agent itself (a summariser, a tool
  result re-saved as the user's words) is signed by the agent's own key
  and is indistinguishable, by signature, from what the user said. Only a
  content check can catch it, and a plausible planted fact cannot be
  caught at all. Binding origin at ingestion is the agent framework's job
  and is measured separately.

The scheme is HMAC-SHA256 over ``user_id``, ``source`` and ``text`` with a
per-user secret. It is a model, enough to score whether a store verifies
at all; a real deployment would use per-writer asymmetric keys and rotate
them. Real tools accept the signature as metadata and ignore it, which is
the finding.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


class Keyring:
    """One secret per user, created on first use."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}

    def key(self, user_id: str) -> bytes:
        if user_id not in self._keys:
            self._keys[user_id] = secrets.token_bytes(32)
        return self._keys[user_id]

    def sign(self, user_id: str, source: str, text: str) -> str:
        return hmac.new(self.key(user_id), _payload(user_id, source, text),
                        hashlib.sha256).hexdigest()

    def verify(self, user_id: str, source: str, text: str,
               signature: str | None) -> bool:
        if not signature:
            return False
        expected = self.sign(user_id, source, text)
        return hmac.compare_digest(expected, signature)


def _payload(user_id: str, source: str, text: str) -> bytes:
    return f"{user_id}\x1f{source}\x1f{text}".encode("utf-8")


#: The keyring the attacks sign genuine writes with. A store under test
#: that wants to verify (the defended reference does) reads it from here.
#: Real tools never see it; they get the signature as metadata only.
KEYRING = Keyring()
