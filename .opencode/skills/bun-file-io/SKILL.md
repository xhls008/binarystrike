---
name: bun-file-io
description: Prefer safe Bun file APIs and project-confined directory helpers when implementing BinaryStrike tools
category: development
version: "1.0"
---

# Bun File I/O

Use this skill when adding or changing BinaryStrike file-backed ledgers,
analysis artifacts, or report outputs. Resolve paths against the active project
directory and keep every write inside that directory.

## Preferred APIs

- Use `Bun.file(path)` with `exists()`, `text()`, `json()`, `bytes()`, or
  `arrayBuffer()` for file reads.
- Use `Bun.write(path, value)` for complete file writes.
- Use `Bun.which(command)` before proposing or invoking an optional executable.
- Use `node:fs/promises` only for directory operations such as `mkdir` and
  recursive directory traversal.
- Use `Bun.Glob` or bounded directory scans instead of unbounded recursive
  reads.

## Project confinement

1. Resolve user paths against the active project root.
2. Reject absolute paths and symlinks that resolve outside the root.
3. Create report/evidence directories before calling `realpath` on them.
4. Never write analysis output next to an input binary unless the caller gave
   an explicit project-relative output directory.

## Evidence and errors

- Record the input path, SHA-256, size, and analysis timestamp in durable
  artifacts when a tool produces evidence.
- Keep raw requests, responses, traces, and generated scripts under
  `.binarystrike/reports/`.
- Bound strings, directory entries, and tool output before injecting them into
  model context.
- Prefer early validation and promise error propagation over broad catch-all
  handlers; do not turn a failed read or failed security tool into a fabricated
  result.
