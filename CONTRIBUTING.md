# Contributing to agmi

agmi is a scorecard. Its value is that every cell was produced the same way, so the rules below are the point of the project, not paperwork. They apply to every row, including rows the maintainer of agmi adds herself.

## How a tool gets a row

1. **Seed and read through the tool's own API.** The adapter writes memories the way a user of that tool would, and reads them back the way the tool's users would. The raw store is touched only during the attack step, never to seed or to verify.
2. **The tool gives the verdict.** `verify()` returns what the tool itself says after a reload. If the tool loads the altered store and raises, refuses or reports the problem, the cell is a detection. If it loads and serves the altered data, the cell is accepted. Never infer detection from the adapter's own checks.
3. **Name the detection point.** Say where the tool would catch the edit: on the read path (the call that returns memories to the agent) or in a separate audit call the operator has to make. Both count under rule 2, but they are different guarantees and the scorecard shows which one it is.
4. **Pin the version.** Every row states the library version it was measured on, and the test for that row is pinned so it fails the day the library changes its behaviour. A re-measurement on a newer version is a separate PR that updates the version, the row and the README note together.
5. **Runs offline in under a minute.** No hosted APIs, no model downloads, no Docker required in tests. An embedded database is fine.

## Rows submitted by a tool's own maintainer

Maintainers are welcome to submit their own tool. Those rows land only after agmi reproduces them independently, and the README marks them: "submitted by the <tool> maintainer, reproduced independently by agmi on <version>". Leave accepted cells as measured. If a claim in the README goes beyond what the row measured, it will be asked to come out.

## Models and reference rows

A re-implementation of a tool is welcome as a reference target and must be labelled `(model)` in the scorecard. It is never presented as a measurement of the real library.

## New attacks

One attack, one precise rule for what counts as detected, no heuristics. Write it once against the `MemoryAdapter` interface so it runs on every adapter. If an adapter needs a hook to express the attack honestly, add the hook to `MemoryAdapter` with a safe default.

## Findings

Gaps that are by design are reported in public as design gaps. Anything that looks like an actual vulnerability, such as code execution from a stored payload, goes to the tool's maintainers privately first. See SECURITY.md.

## Before opening a PR

`PYTHONPATH=. python3 -m pytest tests/ -q` must pass, and `PYTHONPATH=. python3 agmi/full_runner.py` must print your row beside the existing ones.
