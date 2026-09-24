import { Blackboard } from "./blackboard.js"
import { Chain } from "./chain.js"
import { Finding } from "./finding.js"

/**
 * A read-only progress projection for BinaryStrike.
 *
 * V1's methodology engine persisted session state in its database and used
 * that state to drive a scheduler.  V2 deliberately does neither: phase
 * progress is derived from the current blackboard snapshot and finding
 * ledger, so an agent can use it as context without being forced down a
 * pre-defined path.
 */
export namespace Methodology {
  export type Status = "not_started" | "in_progress" | "completed"

  export type Phase = {
    id: string
    name: string
    status: Status
    evidence_count: number
    next: string
  }

  export type Violation = {
    gate: string
    severity: "warning" | "blocking"
    message: string
  }

  export type Result = {
    phases: Phase[]
    completed_count: number
    total_count: number
    completion_percent: number
    current_phase?: string
    coverage: {
      /** Planned checks are not part of the V2 blackboard contract yet. */
      total_checks: number | null
      completed_checks: number
      vulnerable_checks: number
      coverage_percent: number | null
      unknown_verdict_checks: number
      total_entries: number
    }
    findings: {
      total: number
      pending: number
      approved: number
      duplicate: number
      fixed: number
      ignored: number
      by_severity: Record<string, number>
    }
    graph: {
      facts: number
      goals: number
      steps: number
      intents: number
      hints: number
      edges: number
    }
    violations: Violation[]
    next_steps: string[]
    chains: Chain.Candidate[]
  }

  type Definition = {
    id: string
    name: string
    tags: string[]
    next: string
  }

  const definitions: Definition[] = [
    {
      id: "scope_analysis",
      name: "Scope and asset analysis",
      tags: ["scope", "scope-analysis", "asset", "target"],
      next: "Record the authorized asset, binary path, hash, or target boundary as a fact.",
    },
    {
      id: "binary_triage",
      name: "Binary and firmware triage",
      tags: ["binary", "firmware", "format", "architecture", "metadata", "triage"],
      next: "Run analyze_binary or analyze_firmware and preserve the result as a fact.",
    },
    {
      id: "static_analysis",
      name: "Static reverse engineering",
      tags: ["reverse-engineering", "static", "decompile", "disassembly", "imports", "symbols"],
      next: "Inspect the relevant functions, data flow, and parser boundaries; link observations to the triage fact.",
    },
    {
      id: "dynamic_analysis",
      name: "Dynamic validation",
      tags: ["dynamic", "debug", "debugger", "trace", "runtime", "retest"],
      next: "Verify the suspected path with a bounded debugger, trace, or authorized retest.",
    },
    {
      id: "vulnerability_validation",
      name: "Vulnerability validation",
      tags: ["vulnerability", "finding", "cwe", "exploit", "poc", "validation"],
      next: "Turn a supported hint into a finding fact only after reproducible evidence is available.",
    },
    {
      id: "coverage_review",
      name: "Coverage review",
      tags: ["coverage", "tested", "not-vulnerable", "not_vulnerable"],
      next: "Record both positive and clean coverage facts, then avoid repeating the same asset/class check.",
    },
    {
      id: "reporting",
      name: "Reporting and handoff",
      tags: ["report", "reporting", "handoff", "deliverable"],
      next: "Export the selected finding IDs with request, response, and artifact evidence.",
    },
  ]

  function text(entry: Blackboard.Entry) {
    return [entry.title, entry.body, entry.source ?? "", ...entry.tags].join(" ").toLowerCase()
  }

  function matches(entry: Blackboard.Entry, tags: readonly string[]) {
    const value = text(entry)
    return tags.some((tag) => value.includes(tag.toLowerCase()))
  }

  function active(entry: Blackboard.Entry) {
    return entry.status !== "rejected" && entry.status !== "superseded"
  }

  function checkpoint(entry: Blackboard.Entry, definition: Definition) {
    return (
      active(entry) &&
      entry.tags.includes(`phase:${definition.id}`) &&
      Boolean(entry.source?.trim()) &&
      entry.confidence !== "unverified"
    )
  }

  function phaseStatus(input: { facts: Blackboard.Entry[]; candidates: Blackboard.Entry[]; definition: Definition }) {
    // A phase is complete only when a producer explicitly says so.  Matching
    // prose (or a generic tag such as `binary`) is useful context, but is not
    // a completion signal and must never advance the methodology projection.
    const done = input.facts.filter((entry) => checkpoint(entry, input.definition))
    if (done.length) return { status: "completed" as const, count: done.length }

    // Candidates still provide observational progress.  Trusted facts that
    // lack an explicit checkpoint do too, without being mistaken for done.
    const tagged = (entry: Blackboard.Entry) => entry.tags.includes(`phase:${input.definition.id}`)
    const pending = input.candidates.filter((entry) => active(entry) && (tagged(entry) || matches(entry, input.definition.tags)))
    const observed = input.facts.filter(
      (entry) =>
        active(entry) && (tagged(entry) || (entry.confidence !== "unverified" && matches(entry, input.definition.tags))),
    )
    if (pending.length || observed.length) return { status: "in_progress" as const, count: pending.length + observed.length }
    return { status: "not_started" as const, count: 0 }
  }

  function coverage(entries: Blackboard.Entry[]) {
    const notes = entries.filter((entry) => active(entry) && entry.tags.includes("coverage"))
    const cells = new Map<string, Blackboard.Entry>()
    for (const entry of [...notes].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
      const key = [
        entry.tags.find((tag) => tag.startsWith("asset:")) ?? "asset:",
        entry.tags.find((tag) => tag.startsWith("class:")) ?? "class:",
        entry.tags.find((tag) => tag.startsWith("scope:")) ?? "scope:",
      ].join("|")
      cells.set(key, entry)
    }
    const current = [...cells.values()]
    const verdict = (entry: Blackboard.Entry) => entry.tags.find((tag) => tag.startsWith("verdict:"))?.slice("verdict:".length)
    const completed = current.length
    const vulnerable = current.filter((entry) => verdict(entry) === "tested_vulnerable").length
    const unknown = current.filter((entry) => !verdict(entry)).length
    return {
      total_checks: null,
      completed_checks: completed,
      vulnerable_checks: vulnerable,
      coverage_percent: null,
      unknown_verdict_checks: unknown,
      total_entries: notes.length,
    }
  }

  function findingSummary(entries: Awaited<ReturnType<typeof Finding.read>>) {
    const counts = { pending: 0, approved: 0, duplicate: 0, fixed: 0, ignored: 0 }
    const by_severity: Record<string, number> = {}
    for (const entry of entries) {
      if (entry.status === "new" || entry.status === "open" || (entry.status === "approved" && !entry.fact_id)) {
        counts.pending++
      }
      if (entry.status in counts && (entry.status !== "approved" || Boolean(entry.fact_id))) {
        counts[entry.status as keyof typeof counts]++
      }
      by_severity[entry.severity] = (by_severity[entry.severity] ?? 0) + 1
    }
    return { total: entries.length, ...counts, by_severity }
  }

  export async function status(input: { root: string; include_validation?: boolean }): Promise<Result> {
    const [entries, findings, chains] = await Promise.all([
      Blackboard.read({ root: input.root }),
      Finding.read({ root: input.root }),
      Chain.detect(input.root),
    ])
    const facts = entries.filter((entry) => entry.kind === "fact")
    const candidates = entries.filter((entry) => entry.kind !== "fact")
    const phases = definitions.map((definition) => {
      const current = phaseStatus({ facts, candidates, definition })
      return {
        id: definition.id,
        name: definition.name,
        status: current.status,
        evidence_count: current.count,
        next: definition.next,
      }
    })
    const completed = phases.filter((phase) => phase.status === "completed").length
    const current = phases.find((phase) => phase.status === "in_progress") ?? phases.find((phase) => phase.status === "not_started")
    const pending = entries
      .filter((entry) => entry.kind === "step" && (entry.status === "open" || entry.status === "active"))
      .sort((a, b) => (b.priority ?? 50) - (a.priority ?? 50) || a.created_at.localeCompare(b.created_at))
    const summary = findingSummary(findings)
    const result: Result = {
      phases,
      completed_count: completed,
      total_count: phases.length,
      completion_percent: Math.round((completed / phases.length) * 100),
      current_phase: current?.id,
      coverage: coverage(facts),
      findings: summary,
      graph: {
        facts: facts.length,
        goals: entries.filter((entry) => entry.kind === "goal").length,
        steps: entries.filter((entry) => entry.kind === "step").length,
        intents: entries.filter((entry) => entry.kind === "intent").length,
        hints: entries.filter((entry) => entry.kind === "hint").length,
        edges: entries.reduce((total, entry) => total + entry.parent_ids.length, 0),
      },
      violations: [],
      next_steps: [
        ...(current ? [current.next] : []),
        ...pending.slice(0, 5).map((step) => `Review FGS Step [${step.id}] ${step.title} (priority ${step.priority ?? 50}).`),
      ],
      chains,
    }
    if (!input.include_validation) return result
    const weak = findings.filter(
      (entry) =>
        entry.status === "approved" &&
        Boolean(entry.fact_id) &&
        entry.evidence.length === 0 &&
        !entry.reproduction &&
        !entry.poc &&
        !entry.blackboard_ids?.length,
    )
    result.violations = [
      ...(summary.pending ? [{ gate: "finding_triage", severity: "warning" as const, message: `${summary.pending} finding candidate(s) still need explicit triage.` }] : []),
      ...(weak.length
        ? [
            {
              gate: "evidence_quality" as const,
              severity: "blocking" as const,
              message: `${weak.length} approved finding(s) have no reproducible evidence or linked blackboard fact.`,
            },
          ]
        : []),
      ...(entries.filter((entry) => entry.kind === "fact" && entry.confidence === "unverified").length
        ? [{ gate: "evidence_quality", severity: "warning" as const, message: "Unverified facts are present; validate provenance before reporting." }]
        : []),
    ]
    return result
  }

  export function format(result: Result) {
    const lines = [
      `## BinaryStrike Methodology (${result.completion_percent}%)`,
      `Current phase: ${result.current_phase ?? "none"}`,
      `Coverage: ${
        result.coverage.coverage_percent === null
          ? `${result.coverage.completed_checks} checks (unknown (no planned check inventory))`
          : `${result.coverage.completed_checks}/${result.coverage.total_checks} checks (${result.coverage.coverage_percent}%)`
      }`,
      `Findings: ${result.findings.total} total, ${result.findings.pending} pending`,
      `FGS graph: ${result.graph.goals} goals, ${result.graph.steps} steps, ${result.graph.facts} facts, ${result.graph.intents} intents, ${result.graph.hints} hints, ${result.graph.edges} edges`,
      "",
      "### Phases",
      ...result.phases.map((phase) => `- ${phase.name}: ${phase.status} (${phase.evidence_count})`),
    ]
    if (result.violations.length) {
      lines.push("", "### Validation", ...result.violations.map((item) => `- [${item.severity}] ${item.message}`))
    }
    if (result.next_steps.length) lines.push("", "### Next step", ...result.next_steps.map((step) => `- ${step}`))
    const chains = Chain.format(result.chains)
    if (chains) lines.push("", chains)
    return lines.join("\n")
  }
}
