---
name: Dispute a cell
about: You maintain or know a tool on the scorecard and believe a cell is wrong
title: "Dispute: <tool> / <attack>"
labels: dispute
---

Every cell is a measurement, and measurements can be wrong. This is how one gets re-checked. Fill in what you can; the maintainer reproduces on a second machine, records the outcome here, and either corrects the cell with a changelog line or explains why it stands. Either way the thread stays public.

**The cell**
Row and attack, as shown on the scorecard (for example `mem0-qdrant-local / retrieval_hijack`).

**What you believe it should say, and why**
A defence the adapter bypasses, a configuration the row does not name, a fixture that does not apply to the tool, a bug in the adapter.

**How to see it**
The exact command and library version, ideally `python -m agmi.measure --target ... ` output, or a change to the adapter. If a different configuration is the point, say which argument and we can score it as its own row (see "Configuration rows" in CONTRIBUTING.md).

**Your relation to the tool**
Maintainer, contributor, user, none. Rows and disputes from a tool's maintainers are welcome and are marked as such.
