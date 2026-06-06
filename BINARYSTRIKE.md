# BinaryStrike

This directory is the BinaryStrike development fork based on CyberStrike.

Original CyberStrike backup:

```text
/home/flybear/flybear_data/llm_tools/_backup/CyberStrike-original-20260604-7bec38358
```

Current fork path:

```text
/home/flybear/flybear_data/llm_tools/binarystrike
```

## Phase 0 Scope

BinaryStrike focuses on binary vulnerability research:

- Native binaries
- Shared libraries
- Firmware
- Reverse-engineering databases
- IDA Pro / Ghidra / PyGhidra MCP integrations
- AIDA-style binary analysis services

Fuzzing is intentionally excluded from this phase.

## Initial Changes

- Added `binary-security` native subagent.
- Added disabled-by-default binary MCP templates:
  - `pyghidra`
  - `ida-mcp-rs`
- Added architecture and MCP integration notes:
  - `docs/binarystrike-architecture.md`
  - `docs/binary-mcp-integrations.md`

## Development Notes

The command, config files, package names, and runtime namespaces still use CyberStrike names during this phase. Rename them only after the binary-analysis product layer is stable, because a full rebrand touches package publishing, config discovery, installed paths, generated SDKs, and binary launchers.
