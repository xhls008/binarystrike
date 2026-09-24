import path from "path"
import { mkdir, realpath } from "fs/promises"
import { Blackboard } from "./blackboard.js"
import { Finding as Ledger } from "./finding.js"
import { Methodology } from "./methodology.js"

type Format = "json" | "markdown" | "html"

function safe(input: string) {
  return input.replace(/[^a-zA-Z0-9._-]/g, "_")
}

function escape(input: string) {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;")
}

function inside(root: string, target: string) {
  const relative = path.relative(root, target)
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function output(root: string, session: string | undefined, dir: string | undefined) {
  const target = dir ? path.resolve(root, dir) : path.join(root, ".binarystrike", "reports", safe(session ?? "current"))
  if (!inside(root, target)) throw new Error(`Report output must stay inside ${root}`)
  return target
}

type EvidenceRecord = Report.Evidence & { file: string }

function markdown(input: {
  session: string
  generated: string
  findings: readonly Report.Finding[]
  evidence: readonly EvidenceRecord[]
  methodology: Methodology.Result
}) {
  const lines = [
    "# BinaryStrike Report",
    "",
    `- Session: ${input.session}`,
    `- Generated: ${input.generated}`,
    `- Findings: ${input.findings.length}`,
    `- Evidence: ${input.evidence.length}`,
    `- Methodology: ${input.methodology.completion_percent}%`,
    `- Coverage: ${
      input.methodology.coverage.coverage_percent === null
        ? "unknown (no planned check inventory)"
        : `${input.methodology.coverage.coverage_percent}%`
    }`,
    `- Chain candidates: ${input.methodology.chains.length}`,
    "",
    "## Findings",
    "",
  ]

  if (input.findings.length === 0) {
    lines.push("No findings were supplied.", "")
  }

  for (const finding of input.findings) {
    lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`, "")
    lines.push(`- Status: ${finding.status}`)
    if (finding.cwe) lines.push(`- CWE: ${finding.cwe}`)
    if (finding.location) lines.push(`- Location: ${finding.location}`)
    if (finding.line_start !== undefined) {
      const end = finding.line_end === undefined ? "" : `-${finding.line_end}`
      lines.push(`- Lines: ${finding.line_start}${end}`)
    }
    if (finding.endpoint) lines.push(`- Endpoint: ${finding.endpoint}`)
    if (finding.attack_vector) lines.push(`- Attack vector: ${finding.attack_vector}`)
    if (finding.blackboard_ids?.length) lines.push(`- Blackboard: ${finding.blackboard_ids.join(", ")}`)
    if (finding.blackboard_id) lines.push(`- Hint: ${finding.blackboard_id}`)
    if (finding.intent_id) lines.push(`- Verification intent: ${finding.intent_id}`)
    if (finding.fact_id) lines.push(`- Fact: ${finding.fact_id}`)
    if (finding.confidence) lines.push(`- Confidence: ${finding.confidence}`)
    lines.push("", finding.description, "")
    if (finding.evidence.length) lines.push("#### Evidence", "", ...finding.evidence.map((item) => `- ${item}`), "")
    if (finding.reproduction) lines.push("#### Reproduction", "", finding.reproduction, "")
    if (finding.poc) lines.push("#### Proof Of Concept", "", "```", finding.poc, "```", "")
    if (finding.impact) lines.push("#### Impact", "", finding.impact, "")
    if (finding.business_impact) lines.push("#### Business Impact", "", finding.business_impact, "")
    if (finding.recommendation) lines.push("#### Recommendation", "", finding.recommendation, "")
  }

  lines.push("## Evidence", "")
  if (input.evidence.length === 0) lines.push("No evidence artifacts were supplied.", "")
  for (const item of input.evidence) {
    lines.push(`- ${item.label ?? item.id} (${item.kind}) — ${item.file}`)
  }

  return lines.join("\n")
}

function html(input: { report: string; markdown: string }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>BinaryStrike Report ${escape(input.report)}</title>
  <style>
    body { font: 14px/1.5 system-ui, sans-serif; max-width: 1120px; margin: 32px auto; padding: 0 20px; color: #151515; }
    pre { white-space: pre-wrap; }
  </style>
</head>
<body>
<pre>${escape(input.markdown)}</pre>
</body>
</html>`
}

export namespace Report {
  export type Finding = {
    id?: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    status: string
    title: string
    description: string
    cwe?: string
    location?: string
    line_start?: number
    line_end?: number
    endpoint?: string
    attack_vector?: string
    blackboard_ids?: readonly string[]
    blackboard_id?: string
    intent_id?: string
    fact_id?: string
    confidence?: "confirmed" | "likely" | "unverified"
    evidence: readonly string[]
    reproduction?: string
    poc?: string
    impact?: string
    business_impact?: string
    recommendation?: string
  }

  export type Evidence = {
    id: string
    kind: "request" | "response" | "artifact"
    label?: string
    content: string
  }

  export type Result = {
    session: string
    directory: string
    files: string[]
    findings: number
    evidence: number
    methodology: number
    chains: number
  }

  export async function generate(input: {
    root: string
    session?: string
    findings?: readonly Finding[]
    finding_ids?: readonly string[]
    evidence?: readonly Evidence[]
    format?: readonly Format[]
    dir?: string
  }): Promise<Result> {
    const session = input.session ?? "current"
    const dir = output(input.root, session, input.dir)
    const formats = input.format?.length ? input.format : (["json", "markdown", "html"] as Format[])
    const generated = new Date().toISOString()
    const files: string[] = []
    const methodology = await Methodology.status({ root: input.root, include_validation: true })
    const findings = input.findings ?? (await Ledger.read({ root: input.root })).filter((finding) => input.finding_ids?.includes(finding.id))
    if (!input.findings && !input.finding_ids) throw new Error("Report requires findings or finding_ids")
    if (input.finding_ids) {
      const known = new Set((await Ledger.read({ root: input.root })).map((finding) => finding.id))
      const missing = input.finding_ids.find((id) => !known.has(id))
      if (missing) throw new Error(`Report finding not found: ${missing}`)
    }
    const ids = [
      ...new Set(
        findings.flatMap((finding) => [
          ...(finding.blackboard_ids ?? []),
          ...(finding.blackboard_id ? [finding.blackboard_id] : []),
          ...(finding.intent_id ? [finding.intent_id] : []),
          ...(finding.fact_id ? [finding.fact_id] : []),
        ]),
      ),
    ]
    if (ids.length) {
      const known = new Set((await Blackboard.read({ root: input.root })).map((entry) => entry.id))
      const missing = ids.find((id) => !known.has(id))
      if (missing) throw new Error(`Report blackboard entry not found: ${missing}`)
    }
    const evidence = (input.evidence ?? []).map((item) => ({
      ...item,
      file: path.join("evidence", `${safe(item.id)}.txt`),
    }))

    await mkdir(dir, { recursive: true })
    if (!inside(input.root, await realpath(dir))) throw new Error(`Report output must stay inside ${input.root}`)
    if (evidence.length) {
      await mkdir(path.join(dir, "evidence"), { recursive: true })
      files.push(
        ...(await Promise.all(
          evidence.map(async (item) => {
            const file = path.join(dir, item.file)
            await Bun.write(file, item.content)
            return file
          }),
        )),
      )
    }
    if (formats.includes("json")) {
      files.push(path.join(dir, "report.json"))
      await Bun.write(
        files.at(-1)!,
        JSON.stringify({ session, generated, findings, evidence, methodology, chains: methodology.chains }, null, 2),
      )
    }

    const report = markdown({ session, generated, findings, evidence, methodology })
    if (formats.includes("markdown")) {
      files.push(path.join(dir, "report.md"))
      await Bun.write(files.at(-1)!, report)
    }
    if (formats.includes("html")) {
      files.push(path.join(dir, "report.html"))
      await Bun.write(files.at(-1)!, html({ report: session, markdown: report }))
    }

    return {
      session,
      directory: dir,
      files,
      findings: findings.length,
      evidence: evidence.length,
      methodology: methodology.completion_percent,
      chains: methodology.chains.length,
    }
  }
}
