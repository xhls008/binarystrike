---
name: decompileai-lite
description: Use DecompileAI Lite and AIDA services for authorized binary SCA, indirect-call prediction, CiRCLE jobs, semantic embeddings, and project memory.
category: binary-analysis
version: "1.0"
author: binarystrike-official
tags: [binary, reverse-engineering, decompileai, aida, mcp, sca, callee, circle, openbinquery, clap]
tech_stack: [elf, pe, macho, firmware, ida, ghidra]
cwe_ids: []
chains_with: [dynamic-debugging]
prerequisites: []
severity_boost: {}
---

# DecompileAI Lite Workflow

Use this skill only for authorized binaries, firmware images, local reverse-engineering projects, or explicit assessment scope.

## Service Map

Use DecompileAI Lite and AIDA capabilities by task:

- `decompileai-lite-memory`: project memory, notes, durable facts, and cross-session recall through the local DecompileAI Lite agent.
- `aida_health`: compact health check for the AIDA proxy and service endpoints.
- `aida_sca_*`: binary dependency, library, and likely version analysis.
- `aida_callee_*`: indirect-call, callback, vtable, and function-pointer target prediction.
- `aida_circle_*`: heavier CiRCLE analysis jobs for structure, type, and semantic recovery suggestions.
- `aida_openbinquery_*`: assembly or natural-language description embeddings and similar-function search.
- `aida_clap_*`: cross-modal text/ASM semantic search.
- `aida_tei_embed`: internal SCA-style embeddings only when explicitly needed.

## MCP Setup

BinaryStrike ships disabled MCP templates for DecompileAI Lite/AIDA. Enable them only when the local services exist by setting `disabled` to `false` under `mcp.servers` in `opencode.jsonc` or `.opencode/opencode.jsonc`:

```jsonc
{
  "mcp": {
    "servers": {
      "decompileai-lite-memory": {
        "disabled": false,
      },
      "aida-services": {
        "disabled": false,
      },
    },
  },
}
```

The default commands are portable templates. If `decompileai-lite-agent` or `aida-mcp-server` is not on `PATH`, override the `command` array with the absolute path to the local DecompileAI Lite agent or AIDA MCP wrapper before enabling it.

Expected local endpoints:

```text
AIDA host base URL: http://127.0.0.1:18000
AIDA container URL: http://aida-proxy
Public port:        18000 only
Runtime:            CPU only
```

Do not call old direct service ports such as `8000`, `5001`, `8090`, `8001`, `5007`, or `8003`.

## Health First

Before using AIDA analysis tools, run the health tool or bounded curl checks:

```bash
curl -sS http://127.0.0.1:18000/health
curl -sS http://127.0.0.1:18000/sca/api/v1/health
curl -sS http://127.0.0.1:18000/callee/health
curl -sS http://127.0.0.1:18000/openbinquery/health
curl -sS http://127.0.0.1:18000/clap/health
curl -sS http://127.0.0.1:18000/circle/api/v1/healthz
```

If the health check fails, report which service is unavailable and fall back to local static analysis instead of inventing service results.

## Robust Request Rules

- Use local file paths and multipart upload for binaries. Never paste binary content into prompts.
- Verify the file exists and record `file`, `sha256sum`, size, and architecture before submission.
- Submit SCA, CALLEE, and CiRCLE jobs asynchronously, return the `job_id`, then poll status.
- Poll every 5-10 seconds. Fetch results only after the job is completed.
- Fetch CiRCLE logs when a job fails before deciding next steps.
- Keep result summaries compact. Do not return raw embeddings or huge result arrays unless the user asks for them.
- Treat CALLEE and CiRCLE outputs as predictions. Confirm high-impact conclusions with xrefs, types, decompiler output, runtime traces, or manual review.

## Output Locations

Store durable evidence under the current project:

```text
.binarystrike/reports/<session-id>/decompileai/
```

Suggested artifacts:

- `sample.json`: path, hash, size, format, architecture, and analysis timestamp.
- `sca_result.json` and `sca_summary.md`: dependency and version matches.
- `callee_predictions.json` and `callee_summary.md`: indirect-call predictions and confidence notes.
- `circle_result.json`, `circle_log.txt`, and `circle_summary.md`: CiRCLE outputs and reviewed conclusions.
- `openbinquery_searches.jsonl` and `clap_searches.jsonl`: semantic search inputs, models, top matches, and analyst notes.
- `memory_notes.jsonl`: DecompileAI Lite memory facts saved or recalled during the session.

## Reporting Standard

Only report a vulnerability when evidence ties the service output to a real bug:

- Binary path and SHA-256.
- Function name and address, or file offset when symbols are unavailable.
- Service output used, including job ID or search record.
- User-controlled source, transformation path, sink, and missing validation.
- Reproduction or verification steps.
- Confidence label: `CONFIRMED`, `LIKELY`, or `UNVERIFIED`.

Do not turn dependency matches, embedding neighbors, or predicted indirect targets into confirmed findings without verification.
