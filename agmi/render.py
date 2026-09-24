# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Generate the published scorecard tables from a results file, and check
that what is published still matches what was measured.

    python agmi/full_runner.py --json results/scorecard.json
    python -m agmi.render results/scorecard.json docs/scorecard.md
    python -m agmi.render results/scorecard.json docs/scorecard.md --check
    python -m agmi.render results/scorecard.json --compare results/ci.json

The tables people read are generated from the results file, never typed by
hand, so a transcription error cannot reach the README or the site. The
``--check`` form fails when the Markdown on disk differs from what the
results file renders to; CI runs it. The ``--compare`` form fails when two
results files disagree on any cell both of them measured, which is how CI's
own run is held against the committed file.
"""

from __future__ import annotations

import argparse
import json
import sys

AT_REST = ["tamper", "truncate", "delete_middle", "reorder", "forge"]
FRONT_DOOR = ["memory_injection", "cross_session_bleed", "retrieval_hijack",
              "indirect_prompt_injection", "update_poisoning", "metadata_poisoning"]
SHORT = {"tamper": "tamper", "truncate": "truncate", "delete_middle": "delete middle",
         "reorder": "reorder", "forge": "forge", "memory_injection": "planted fact",
         "cross_session_bleed": "cross-user leak", "retrieval_hijack": "retrieval hijack",
         "indirect_prompt_injection": "hidden instruction",
         "update_poisoning": "false correction", "metadata_poisoning": "self-tagged trust"}


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _table(rows: list[dict], names: list[str], with_point: bool) -> list[str]:
    head = ["Target"] + (["Checked at"] if with_point else []) + [SHORT[n] for n in names]
    out = ["| " + " | ".join(head) + " |",
           "|" + "|".join("---" for _ in head) + "|"]
    for r in rows:
        if all(r["cells"][n]["status"] == "n/a" for n in names):
            continue
        cells = [r["label"]]
        if with_point:
            cells.append(r.get("checked_at") or "n/a")
        cells += [r["cells"][n]["verdict"] for n in names]
        out.append("| " + " | ".join(cells) + " |")
    return out


def render(run: dict) -> str:
    versions = ", ".join(f"{k}@v{v}" for k, v in run["attack_versions"].items())
    attackers = run.get("attackers", {})
    levels = ""
    if attackers:
        levels = (" Attacker levels: at-rest attacks assume store access (level 3); "
                  "front-door attacks assume write access to the memory API (level 2); "
                  "content-only attacks (level 1) are not in this table.")
    lines = [
        "# Scorecard",
        "",
        f"Generated from the results file by `agmi.render`; do not edit by hand. "
        f"Run of {run['date']} on {run['platform']}. Attack versions: {versions}.{levels}",
        "",
        "## Behind the back (at rest)",
        "",
        *_table(run["rows"], AT_REST, with_point=True),
        "",
        "## Through the front door",
        "",
        *_table(run["rows"], FRONT_DOOR, with_point=False),
        "",
        "## Detail per cell",
        "",
    ]
    for r in run["rows"]:
        shown = [(n, c) for n, c in r["cells"].items() if c["status"] != "n/a"]
        if not shown:
            continue
        lines.append(f"### {r['label']}")
        lines.append("")
        if r.get("measured_on"):
            lines.append(f"Measured on: {r['measured_on']}")
            lines.append("")
        for n, c in shown:
            lines.append(f"- `{n}`: {c['verdict']}. {c['detail']}".rstrip(". ") + ".")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def compare(a: dict, b: dict) -> list[str]:
    """Cells measured in both runs (status not n/a in either) must agree."""
    diffs = []
    rows_b = {r["label"]: r for r in b["rows"]}
    for ra in a["rows"]:
        rb = rows_b.get(ra["label"])
        if rb is None:
            continue
        for n, ca in ra["cells"].items():
            cb = rb["cells"].get(n)
            if cb is None or ca["status"] == "n/a" or cb["status"] == "n/a":
                continue
            if ca["status"] != cb["status"]:
                diffs.append(f"{ra['label']} / {n}: {ca['status']} vs {cb['status']}")
    return diffs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agmi.render")
    ap.add_argument("results")
    ap.add_argument("markdown", nargs="?")
    ap.add_argument("--check", action="store_true",
                    help="fail if MARKDOWN differs from what RESULTS renders to")
    ap.add_argument("--compare", metavar="OTHER",
                    help="fail if RESULTS and OTHER disagree on a measured cell")
    args = ap.parse_args(argv)
    run = load(args.results)
    if args.compare:
        diffs = compare(run, load(args.compare))
        if diffs:
            print("measured cells disagree:\n  " + "\n  ".join(diffs), file=sys.stderr)
            return 1
        print("measured cells agree")
        return 0
    text = render(run)
    if args.markdown and args.check:
        with open(args.markdown, encoding="utf-8") as fh:
            if fh.read() != text:
                print(f"{args.markdown} is out of date; regenerate it from "
                      f"{args.results}", file=sys.stderr)
                return 1
        print(f"{args.markdown} matches {args.results}")
        return 0
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.markdown}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
