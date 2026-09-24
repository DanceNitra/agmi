# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The authorisation gate.

An active tool that hunts for a way in is a weapon the moment it is pointed
at a system its user does not own. The gate is the difference between a
security tool and an attack tool, so it runs before any target is touched
and it fails closed.

A library target (an in-process adapter the caller constructed) is always
allowed: the caller already holds the object, so there is nothing to
authorise. A network target (a URL) is allowed only when the caller has
proven control of it: either a token in an environment variable named for
the host, or a one-line consent file on disk listing the host. Anything
else raises, and the hunt never starts.

This is deliberately strict and deliberately visible. It is not DRM; a
determined user can edit the file. The point is that pointing the agent at
someone else's server is never the default and never silent: it takes a
deliberate, auditable act by the operator, and the run records which
authorisation it used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class NotAuthorised(Exception):
    """Raised before any target is touched when authorisation is absent."""


@dataclass
class Authorisation:
    kind: str        # "library", "env-token", "consent-file"
    detail: str      # what proved it, for the report


CONSENT_FILE_ENV = "AGMI_CONSENT_FILE"


def authorise_library() -> Authorisation:
    return Authorisation("library", "in-process adapter held by the caller")


def authorise_url(url: str) -> Authorisation:
    """Allow a network target only on proven control of its host."""
    host = urlparse(url).hostname or ""
    if host in ("127.0.0.1", "localhost", "::1"):
        return Authorisation("localhost", "target is the caller's own loopback")
    token_var = "AGMI_TARGET_TOKEN_" + host.replace(".", "_").replace("-", "_").upper()
    if os.environ.get(token_var):
        return Authorisation("env-token", f"token in {token_var}")
    consent = os.environ.get(CONSENT_FILE_ENV)
    if consent:
        path = Path(consent)
        if path.is_file():
            hosts = {line.strip() for line in path.read_text().splitlines()
                     if line.strip() and not line.startswith("#")}
            if host in hosts:
                return Authorisation("consent-file",
                                     f"{host} listed in {path}")
    raise NotAuthorised(
        f"no authorisation for {host!r}. To test a host you control, either "
        f"set {token_var} to any non-empty value, or list the host in a file "
        f"and point {CONSENT_FILE_ENV} at it. The agent never touches a "
        f"target without one of these.")
