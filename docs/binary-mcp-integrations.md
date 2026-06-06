# Binary MCP Integrations

BinaryStrike should integrate reverse-engineering tools through MCP instead of embedding them in the main runtime. Most IDA/Ghidra servers require local GUI/headless setup, so the built-in config keeps binary MCP entries disabled by default.

## Built-In Disabled Entries

`packages/cyberstrike/src/config/config.ts` includes these optional MCP templates:

```jsonc
{
  "mcp": {
    "pyghidra": {
      "type": "local",
      "command": ["uvx", "pyghidra-mcp"],
      "enabled": false,
      "timeout": 30000,
    },
    "ida-mcp-rs": {
      "type": "local",
      "command": ["ida-mcp"],
      "enabled": false,
      "timeout": 30000,
    },
  },
}
```

Enable a server from the TUI MCP dialog, or override it in `cyberstrike.jsonc` / `.cyberstrike/cyberstrike.jsonc`:

```jsonc
{
  "mcp": {
    "pyghidra": {
      "type": "local",
      "command": ["uvx", "pyghidra-mcp"],
      "enabled": true,
      "timeout": 30000,
    },
  },
}
```

## Candidate Open-Source MCP Projects

| Project                     | Backend         | Integration Mode          | Notes                                                                       |
| --------------------------- | --------------- | ------------------------- | --------------------------------------------------------------------------- |
| `mrexodia/ida-pro-mcp`      | IDA Pro         | Local MCP server/plugin   | Good candidate for interactive IDA databases. Requires local IDA setup.     |
| `blacktop/ida-mcp-rs`       | IDA Pro         | Local MCP server          | Rust implementation; good candidate for packaged local server flow.         |
| `13bm/GhidraMCP`            | Ghidra          | Ghidra extension/server   | Good candidate for GUI-assisted Ghidra projects.                            |
| `clearbluejar/pyghidra-mcp` | Ghidra/PyGhidra | Local stdio MCP via `uvx` | Best first default candidate because it can be launched as a local command. |

Reference links:

- https://github.com/mrexodia/ida-pro-mcp
- https://github.com/blacktop/ida-mcp-rs
- https://github.com/13bm/GhidraMCP
- https://github.com/clearbluejar/pyghidra-mcp

## Recommended Tool Contract

Normalize MCP tool outputs into these concepts before the agent reasons over them:

```text
sample
  path
  sha256
  format
  arch
  bitness
  endian
  protections

function
  name
  address
  size
  source_tool
  decompiler_summary
  callers
  callees
  strings
  imports
  risk_tags

finding_evidence
  sample_sha256
  function_address
  source
  sink
  missing_check
  reproduction
  confidence
```

## First Integration Tasks

1. Add a small adapter that maps MCP tool names into stable BinaryStrike concepts.
2. Add sample hashing and metadata extraction before any MCP analysis.
3. Teach the UI to show MCP server health for binary backends separately from web/security MCP servers.
4. Extend `report_vulnerability` metadata with binary fields:
   - `sample_sha256`
   - `function_name`
   - `function_address`
   - `file_offset`
   - `cwe`
   - `evidence_source`
   - `confidence`

## Operational Constraints

- Keep IDA/Ghidra servers disabled by default.
- Do not run unknown binaries unless the user opts into sandboxed execution.
- Store decompiler output as artifacts and summarize it in the LLM context.
- Do not add fuzzing MCPs in this phase.
