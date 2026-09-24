---
name: blackboard
description: Coordinate BinaryStrike analysis through a project-local fact, intent, and hint graph
category: agent-coordination
version: "1.0"
---

# BinaryStrike Blackboard

Use the project-local blackboard when analysis needs to preserve shared context
across turns, agents, or human review. It is an append-only event stream folded
into a current graph; it is not a hidden scheduler or a replacement for model
judgment.

## Entry semantics

- **Fact** — an observed, reproducible piece of evidence. Include the source,
  location, hash, command output, or other provenance and set confidence
  honestly.
- **Intent** — a proposed next action or question. Link it to the fact or hint
  that motivated it. An intent is not evidence until a later fact supports it.
- **Hint** — a provisional lead, alternative interpretation, or hand-off. Keep
  it explicitly uncertain and link it to the relevant parent entries.
- **Goal** — the completion condition for the current search. Goals are state
  descriptions, not an instruction to run a fixed workflow.
- **Step** — a prioritized candidate action that may produce a new Fact. Adding
  a Step never executes it; link it to its Goal and any supporting Facts.

For new search-driven work, prefer the FGS tools (`fgs_read`,
`fgs_create_goal`, `fgs_add_step`, and `submit_fact`). The older Intent kind is
kept for Finding validation compatibility.

Use `blackboard_write` to append entries and `parent_ids` to form causal edges.
If a relationship is discovered after an entry is created, use
`blackboard_update` with `parent_ids`; unknown parents and cycles are rejected.
Use `blackboard_update` to close an intent (`completed` or `rejected`) or mark
an entry `superseded`; do not rewrite history. Use `blackboard_read` to obtain
the current graph and a compact prompt-ready context. Request
`include_history: true` when reviewing the diachronic event timeline.
Finding candidates use the same graph instead of a second coordination channel:
`record_finding` writes an unverified **hint** (linked to any cited facts).
When a Goal already exists, pass its `goal_id`; `triage_finding` with
`status: open` then adds an FGS **step** (and the compatibility **intent**) for
bounded verification. `status: approved` completes the linked work and appends
a **fact** parented by the step when present. A duplicate rejects its work,
supersedes the hint, and links it to the canonical candidate. `fixed` and
`ignored` close linked work without asserting a vulnerability. The finding
ledger remains the durable report-oriented projection; the blackboard is the
shared, causal context. Pending candidates are also injected for the
`binary-security` agent; use `get_findings` for the complete ledger and
`triage_finding` before export.

`methodology_status(include_validation: true)` adds an evidence-quality gate:
an approved finding must retain reproducible evidence or cite a blackboard fact
before it is ready for reporting.

## Coordination rules

1. Record facts before proposing intents that depend on them.
2. Never present a hint or intent as a confirmed vulnerability.
3. Prefer one precise entry over a large transcript dump.
4. Preserve provenance in `source` and put stable identifiers in tags when a
   finding, report, or retest refers back to the entry.
5. Link new observations to the entries they confirm, contradict, or refine;
   the graph's edges are the shared context between independent workers.

## Coverage facts

Use `record_coverage_note` after a real test reaches a verdict, including clean
results. Use `get_coverage_notes` before starting a branch to check whether the
same vulnerability class was already tested for the asset. Coverage notes are
facts with searchable `asset`, `class`, and `scope` tags; they are not a claim
that every other asset has the same result unless the scope is `wide`.
