import { Blackboard } from "./blackboard.js"

export namespace Coverage {
  export type Scope = "wide" | "local"
  export type Verdict = "tested_vulnerable" | "tested_not_vulnerable" | "not_applicable"

  export type Note = {
    id: string
    asset: string
    class: string
    scope: Scope
    note: string
    request_id?: string
    verdict?: Verdict
    technique?: string
    intel_id?: string
    created_at: string
  }

  function text(value: string, name: string) {
    const result = value.trim()
    if (!result) throw new Error(`Coverage ${name} must not be empty`)
    return result
  }

  function current(entry: Blackboard.Entry) {
    return entry.status !== "rejected" && entry.status !== "superseded"
  }

  function tags(input: { asset: string; class: string; scope: Scope; verdict?: Verdict }) {
    return [
      `coverage`,
      `asset:${input.asset}`,
      `class:${input.class}`,
      `scope:${input.scope}`,
      ...(input.verdict ? [`verdict:${input.verdict}`] : []),
    ]
  }

  function note(entry: Blackboard.Entry): Note {
    const asset = entry.tags.find((tag) => tag.startsWith("asset:"))?.slice("asset:".length) ?? ""
    const kind = entry.tags.find((tag) => tag.startsWith("class:"))?.slice("class:".length) ?? ""
    const scope = entry.tags.find((tag) => tag.startsWith("scope:"))?.slice("scope:".length) as Scope
    const verdict = entry.tags.find((tag) => tag.startsWith("verdict:"))?.slice("verdict:".length) as Verdict | undefined
    const technique = entry.tags.find((tag) => tag.startsWith("technique:"))?.slice("technique:".length)
    const intel_id = entry.tags.find((tag) => tag.startsWith("intel:"))?.slice("intel:".length)
    return {
      id: entry.id,
      asset,
      class: kind,
      scope,
      note: entry.body,
      request_id: entry.source,
      ...(verdict ? { verdict } : {}),
      ...(technique ? { technique } : {}),
      ...(intel_id ? { intel_id } : {}),
      created_at: entry.created_at,
    }
  }

  export async function record(input: {
    root: string
    asset: string
    class: string
    scope: Scope
    note: string
    request_id?: string
    verdict?: Verdict
  }) {
    const asset = text(input.asset, "asset")
    const kind = text(input.class, "class")
    const body = text(input.note, "note")
    const labels = tags({ asset, class: kind, scope: input.scope, verdict: input.verdict })
    const entries = await Blackboard.read({ root: input.root, kind: ["fact"] })
    const duplicate = entries.find((entry) => current(entry) && labels.every((tag) => entry.tags.includes(tag)))
    if (duplicate) return { duplicate: true, note: note(duplicate) }
    const entry = await Blackboard.write({
      root: input.root,
      kind: "fact",
      title: `Coverage: ${kind} @ ${asset}`,
      body,
      source: input.request_id,
      confidence: "confirmed",
      tags: labels,
    })
    return { duplicate: false, note: note(entry) }
  }

  export async function query(input: {
    root: string
    asset?: string
    class?: string
    scope?: Scope
    limit?: number
  }) {
    const entries = await Blackboard.read({ root: input.root, kind: ["fact"] })
    return entries
      .filter((entry) => current(entry) && entry.tags.includes("coverage"))
      .map(note)
      .filter(
        (entry) =>
          (input.asset === undefined || entry.asset === input.asset.trim()) &&
          (input.class === undefined || entry.class === input.class.trim()) &&
          (input.scope === undefined || entry.scope === input.scope),
      )
      .slice(-(input.limit ?? 100))
  }

  export async function recordCheck(input: {
    root: string
    intel_id: string
    asset: string
    class: string
    scope: Scope
    status: Verdict
    technique?: string
    evidence?: string
  }) {
    const asset = text(input.asset, "asset")
    const kind = text(input.class, "class")
    const intel_id = text(input.intel_id, "intel_id")
    const technique = input.technique?.trim()
    const evidence = input.evidence?.trim()
    if (input.status === "tested_vulnerable" && !evidence) {
      throw new Error("Coverage vulnerable checks require evidence")
    }
    const parent = (await Blackboard.read({ root: input.root })).find((entry) => current(entry) && entry.id === intel_id)
    if (!parent || !parent.tags.includes("intel")) throw new Error(`Coverage intel entry not found: ${intel_id}`)
    const labels = [
      ...tags({ asset, class: kind, scope: input.scope }),
      "vrt-check",
      `verdict:${input.status}`,
      `intel:${intel_id}`,
      ...(technique ? [`technique:${technique}`] : []),
    ]
    const entry = await Blackboard.write({
      root: input.root,
      kind: "fact",
      title: `VRT: ${kind} @ ${asset}`,
      body: evidence ?? technique ?? `Recorded ${input.status}.`,
      source: technique,
      confidence: input.status === "tested_vulnerable" ? "high" : "confirmed",
      tags: labels,
      parent_ids: [intel_id],
    })
    return { duplicate: false, note: note(entry) }
  }
}
