# BinaryStrike Architecture

BinaryStrike is a CyberStrike-based fork focused on binary vulnerability research. The first development phase keeps CyberStrike's agent runtime, TUI/Web UI, MCP client, plugin system, session storage, and vulnerability reporting, then adds a binary-analysis product layer.

## Product Scope

In scope:
- Native binaries, shared libraries, firmware images, stripped executables, and reverse-engineering databases.
- Static triage, SCA, decompiler-assisted analysis, call graph review, root-cause analysis, and report generation.
- MCP integrations for IDA Pro, Ghidra/PyGhidra, and other reverse-engineering backends.
- AIDA-style services for SCA, indirect-call prediction, embeddings, and large-scale triage.

Out of scope for the first phase:
- Fuzzing campaigns, fuzz harness generation, corpus minimization, and fuzz orchestration.
- Weaponized exploit development.
- Malware execution outside a sandbox.

## Architecture

```text
Binary sample / firmware / RE database
        |
        v
Sample inventory and metadata
        |
        v
MCP analysis layer
  - IDA Pro MCP
  - Ghidra / PyGhidra MCP
  - AIDA MCP services
  - capa / yara / rizin adapters
        |
        v
Binary knowledge model
  - functions
  - xrefs
  - strings
  - imports / exports
  - call graph
  - risky sinks
  - evidence snippets
        |
        v
binary-security agent
        |
        v
Finding report
  - binary hash
  - function/address
  - input path
  - bug class / CWE
  - evidence
  - impact
  - remediation
```

## Reused CyberStrike Components

| Component | Reuse | Notes |
| --- | --- | --- |
| TUI/Web UI | Yes | Keep session, agent switching, MCP status, and findings UI. |
| Agent runtime | Yes | Add `binary-security` as a native subagent. |
| MCP client | Yes | Primary integration path for IDA/Ghidra/AIDA. |
| Plugin/custom tools | Yes | Useful for local wrappers around reverse-engineering tools. |
| `report_vulnerability` | Yes | Extend later with binary-specific metadata fields. |
| HackBrowser/proxy agents | Keep, not central | Not used for binary MVP. |

## MVP Milestones

1. Phase 0: Fork hygiene
   - Keep original CyberStrike backup.
   - Work only under `binarystrike`.
   - Add BinaryStrike architecture docs and binary agent.

2. Phase 1: MCP-based triage
   - Add disabled-by-default IDA/Ghidra MCP templates.
   - Document how to enable local reverse-engineering MCP servers.
   - Teach `binary-security` to use MCP tools through `tool_search` and `load_tools`.

3. Phase 2: Binary evidence model
   - Add binary sample entity: path, hash, architecture, format, protection flags.
   - Add function evidence entity: name, address, tool source, decompiler/assembly summary.
   - Extend vulnerability metadata for binary fields.

4. Phase 3: UI surfaces
   - Add binary sample list.
   - Add function and xref panes.
   - Add finding-to-function linking.

5. Phase 4: Sandboxed execution
   - Run unknown binaries only in a constrained container or VM.
   - Add execution policy, resource limits, and no-network defaults.

## Design Rules

- MCP servers are optional and disabled by default unless they are safe to start without local commercial tools.
- Reverse-engineering tools run outside the main CyberStrike process.
- The agent must produce evidence-backed findings, not speculative vulnerability reports.
- Long-running analysis jobs should be backgrounded and summarized from artifacts.
- Fuzzing remains excluded until a later explicit product phase.
