# Contributing to agmi

Thanks for looking. The most useful contributions, in order:

1. **A new adapter for a real memory or checkpoint store.** Copy
   `agmi/adapters/langgraph_sqlite.py`, keep the same shape, and make sure
   every row in the scorecard is a measurement of the real library, seeded
   and read back through its own API. A model or re-implementation of a
   tool is welcome as a reference target but must be labelled `(model)`.
2. **A new attack class.** One attack, one clear pass/fail rule, no
   heuristics. If an adapter needs a hook to express the attack honestly,
   add the hook to `MemoryAdapter` with a default.
3. **A re-measurement.** If a tool ships an integrity check, the pinned
   test for that tool will fail. Update the version, the scorecard and the
   README note in one PR.

Rules of the road:

- `verify()` returns what the tool itself says. Never infer detection.
- Every measured row states the library version it was measured on.
- Nothing in this repo downloads models or calls hosted APIs in tests.
- Findings that are by design are reported as design gaps, not bugs.
  Anything that looks like a real vulnerability goes to the maintainers
  privately first; see SECURITY.md.

Run `PYTHONPATH=. python3 -m pytest tests/ -q` before opening a PR.
