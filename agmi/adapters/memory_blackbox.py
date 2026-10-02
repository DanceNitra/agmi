# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""memory-blackbox: a signed provenance ledger with a memory-file watcher.

The package (PyPI `memory-blackbox`, Apache 2.0) is a flight recorder for
agent memory: every captured read and write becomes an Ed25519-signed
record in an append-only ledger with a BLAKE3 hash chain and a Merkle
root, and `verify` proves the ledger itself was not edited, gapped or
truncated. Its README places it as post-incident reconstruction, not a
runtime block. For the memory the agent actually reads it offers two
things: a `reconcile` command that flags backend ids with no ledger
record, and a `MemoryMdAdapter` that watches memory files such as
MEMORY.md, keeps a BLAKE3 digest of each, and on every `scan()` records a
provenance write for any file whose digest changed, so an out-of-band
edit is captured and attributable.

This row measures the watcher on a MEMORY.md store, one memory per
line, with a second watched file standing in for the second context. The
agent's read path is the file itself, unchanged, so detection is the
scan: a scan that records a write for the watched file after the edit is
"reported". The agent process stays up between the edit and the scan,
so the watcher's in-process digest is the baseline. The ledger itself is
never edited by the suite; the eight edits target the memory store.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

CTX_FILE = "MEMORY.md"
OTHER_FILE = "AGENTS.md"
CTX = "ctx-A"
OTHER = "ctx-B"
META_SEP = "  <!-- "


class MemoryBlackboxMdAdapter(MemoryAdapter):
    """memory.md watcher, agent process alive across the edit."""

    name = "memory-blackbox-md"
    supports_replay = True
    supports_metadata = True
    detection_point = "audit"

    def __init__(self):
        self._dir: str | None = None
        self._bb = None
        self._watch = None

    # --- lifecycle ---------------------------------------------------------

    def _open_watcher(self):
        from memory_blackbox.adapters.memory_md import MemoryMdAdapter
        from memory_blackbox.capture.engine import MemoryBlackbox
        from memory_blackbox.crypto import keys
        keypath = Path(self._dir) / "signing.key"
        if keypath.exists():
            kp = keys.load(keypath)
        else:
            kp = keys.generate()
            keys.save(kp, keypath)
        self._bb = MemoryBlackbox.open(Path(self._dir) / "blackbox.db", kp)
        self._watch = MemoryMdAdapter(self._bb, self._dir,
                                      filenames=(CTX_FILE, OTHER_FILE))

    def setup(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="agmi-mbb-")
        (Path(self._dir) / CTX_FILE).write_text("", encoding="utf-8")
        (Path(self._dir) / OTHER_FILE).write_text("", encoding="utf-8")
        self._open_watcher()
        self._watch.baseline()

    def teardown(self) -> None:
        try:
            self._bb.ledger.connection.close()
        except Exception:  # noqa: BLE001
            pass
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None

    def _path(self, ctx: str) -> Path:
        return Path(self._dir) / (CTX_FILE if ctx == CTX else OTHER_FILE)

    # --- the tool's own write path: the agent appends a line, the watcher
    # --- captures it on scan ------------------------------------------------

    def _seed_ctx(self, ctx: str, n: int) -> None:
        p = self._path(ctx)
        lines = [f"- agmi-{ctx}-{i}: the limit is {40 + i}{META_SEP}ts={1_700_000_000 + i} -->"
                 for i in range(n)]
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._watch.scan()  # the agent's own write is captured and trusted

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, n)

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER, n)

    # --- raw access, bypassing the tool -----------------------------------

    def _lines(self, ctx: str) -> list[str]:
        text = self._path(ctx).read_text(encoding="utf-8")
        return [ln for ln in text.split("\n") if ln.strip()]

    def _write_lines(self, ctx: str, lines: list[str]) -> None:
        self._path(ctx).write_text("\n".join(lines) + ("\n" if lines else ""),
                                   encoding="utf-8")

    def _read_ctx(self, ctx: str) -> list[Record]:
        return [Record(seq=i, fields={"ctx": ctx, "line": ln})
                for i, ln in enumerate(self._lines(ctx))]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER)

    def write_raw(self, record: Record) -> None:
        lines = self._lines(CTX)
        if record.seq < len(lines):
            lines[record.seq] = record.fields["line"]
        else:
            lines.append(record.fields["line"])
        self._write_lines(CTX, lines)

    def delete_raw(self, seq: int) -> None:
        lines = self._lines(CTX)
        del lines[seq]
        self._write_lines(CTX, lines)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        lines = self._lines(CTX)
        lines[victim_seq] = donor.fields["line"]
        self._write_lines(CTX, lines)

    @staticmethod
    def _split(line: str) -> tuple[str, str]:
        body, _, meta = line.partition(META_SEP)
        return body, meta

    def read_meta(self, seq: int) -> dict:
        _, meta = self._split(self._lines(CTX)[seq])
        return {"raw": meta}

    def write_meta(self, seq: int, meta: dict) -> None:
        lines = self._lines(CTX)
        body, old = self._split(lines[seq])
        new = old.replace("-->", "tampered=1 -->") if meta.get("agmi_meta_tampered") else meta.get("raw", old)
        lines[seq] = body + META_SEP + new
        self._write_lines(CTX, lines)

    def mutate_payload(self, record: Record) -> Record:
        body, meta = self._split(record.fields["line"])
        record.fields["line"] = body + "  [TAMPERED]" + META_SEP + meta
        return record

    def forge_record(self, template: Record) -> Record:
        return Record(seq=template.seq + 1,
                      fields={"ctx": CTX, "line": f"- agmi-forged: the limit is 999{META_SEP}ts=0 -->"})

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return f"{record.fields['ctx']}:{record.seq}"

    def payload_of(self, record):
        return self._split(record.fields["line"])[0]

    def owner_of(self, record):
        return record.fields["ctx"]

    # --- the audit ----------------------------------------------------------

    def reload(self) -> None:
        # The process stays up; the watcher keeps its digests.
        return

    def verify(self) -> bool:
        """A scan that records a write for the agent's memory file means the
        watcher saw an edit the agent did not make."""
        self.verify_detail = None
        changed = self._watch.scan()
        hits = [r for r in changed if str(self._path(CTX)) == (r.memory_id or "")]
        if hits:
            self.verify_detail = (f"scan recorded an out-of-band write to {CTX_FILE} "
                                  f"(record {hits[0].record_id[:8]})")
            return False
        return True
