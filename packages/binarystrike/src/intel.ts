import { Blackboard, type Kind } from "./blackboard.js"

export namespace Intel {
  export type Type =
    | "endpoint"
    | "subdomain"
    | "technology"
    | "credential"
    | "parameter"
    | "vulnerability_hint"
    | "configuration"
    | "api_schema"
    | "authentication_flow"
    | "business_rule"
    | "sensitive_data"
    | "infrastructure"

  export type Confidence = "confirmed" | "high" | "medium" | "low"
  export type Severity = "critical" | "high" | "medium" | "low" | "info"
  export type Status = "new" | "investigating" | "tested" | "exploited" | "reported"

  export type Entry = {
    id: string
    kind: Kind
    type: Type
    severity?: Severity
    title: string
    detail: string
    source?: string
    asset: string
    confidence: Confidence
    tags: string[]
    related_ids: string[]
    status: Status
    created_at: string
    updated_at: string
  }

  type Input = {
    type: Type
    title: string
    asset: string
    detail?: string
    source?: string
    severity?: Severity
    confidence?: Confidence
    tags?: readonly string[]
    related_ids?: readonly string[]
    status?: Status
    target_class?: string
  }

  const types: Type[] = [
    "endpoint",
    "subdomain",
    "technology",
    "credential",
    "parameter",
    "vulnerability_hint",
    "configuration",
    "api_schema",
    "authentication_flow",
    "business_rule",
    "sensitive_data",
    "infrastructure",
  ]

  function text(value: string | undefined, name: string, required = true) {
    const result = value?.trim()
    if (required && !result) throw new Error(`Intel ${name} must not be empty`)
    return result
  }

  function tag(value: string, prefix: string) {
    return `${prefix}:${value}`
  }

  function type(tags: readonly string[]) {
    return tags.find((item): item is `intel-type:${Type}` => item.startsWith("intel-type:"))?.slice(11) as Type
  }

  function value(tags: readonly string[], prefix: string) {
    return tags.find((item) => item.startsWith(`${prefix}:`))?.slice(prefix.length + 1)
  }

  function decode(entry: Blackboard.Entry): Entry {
    const raw = value(entry.tags, "intel-status")
    const confidence = value(entry.tags, "confidence") as Confidence | undefined
    return {
      id: entry.id,
      kind: entry.kind,
      type: type(entry.tags),
      severity: value(entry.tags, "severity") as Severity | undefined,
      title: entry.title,
      detail: entry.body,
      source: entry.source,
      asset: value(entry.tags, "asset") ?? "",
      confidence: confidence ?? "low",
      tags: entry.tags.filter((item) => !item.startsWith("intel") && !item.startsWith("asset:") && !item.startsWith("severity:") && !item.startsWith("confidence:") && !item.startsWith("target:") && !item.startsWith("intel-status:")),
      related_ids: entry.parent_ids,
      status: (raw as Status | undefined) ?? "new",
      created_at: entry.created_at,
      updated_at: entry.updated_at,
    }
  }

  function validType(value: string): value is Type {
    return types.includes(value as Type)
  }

  function labels(input: Input) {
    return [
      "intel",
      tag(input.type, "intel-type"),
      tag(input.asset, "asset"),
      ...(input.severity ? [tag(input.severity, "severity")] : []),
      tag(input.confidence ?? "low", "confidence"),
      tag(input.status ?? "new", "intel-status"),
      ...(input.target_class ? [tag(input.target_class, "target")] : []),
      ...(input.tags ?? []),
    ]
  }

  export async function read(input: { root: string; asset?: string; type?: Type; limit?: number }) {
    const entries = await Blackboard.read({ root: input.root, kind: ["fact", "hint"] })
    const result = entries
      .filter((entry) => entry.tags.includes("intel"))
      .map(decode)
      .filter(
        (entry) =>
          (!input.asset || entry.asset.toLowerCase() === input.asset.trim().toLowerCase()) &&
          (!input.type || entry.type === input.type),
      )
    if (input.limit === undefined) return result
    return result.slice(Math.max(0, result.length - input.limit))
  }

  export async function record(input: { root: string } & Input) {
    const title = text(input.title, "title")!
    const asset = text(input.asset, "asset")!
    const detail = text(input.detail, "detail", false) ?? title
    const related_ids = [...new Set(input.related_ids ?? [])]
    const existing = (await read({ root: input.root })).find(
      (entry) => entry.title.toLowerCase() === title.toLowerCase() && entry.asset.toLowerCase() === asset.toLowerCase() && entry.type === input.type,
    )
    if (existing) return { duplicate: true, entry: existing, vrt_checks_created: 0 }
    const confidence = input.confidence ?? "low"
    const kind = input.type === "vulnerability_hint" || confidence === "low" || confidence === "medium" ? "hint" : "fact"
    const node = await Blackboard.write({
      root: input.root,
      kind,
      title,
      body: detail,
      source: text(input.source, "source", false),
      confidence: confidence === "confirmed" ? "confirmed" : confidence === "high" ? "high" : confidence === "medium" ? "medium" : "low",
      tags: [...new Set(labels({ ...input, title, asset, detail, confidence }))],
      parent_ids: related_ids,
    })
    return { duplicate: false, entry: decode(node), vrt_checks_created: 0 }
  }

  export async function update(input: { root: string; id: string; status?: Status; confidence?: Confidence; detail?: string }) {
    const current = (await read({ root: input.root })).find((entry) => entry.id === input.id)
    if (!current) throw new Error(`Intel entry not found: ${input.id}`)
    const tags = (await Blackboard.read({ root: input.root })).find((entry) => entry.id === input.id)?.tags ?? []
    const patchTags = tags.map((item) => {
      if (input.status && item.startsWith("intel-status:")) return tag(input.status, "intel-status")
      if (input.confidence && item.startsWith("confidence:")) return tag(input.confidence, "confidence")
      return item
    })
    const updated = await Blackboard.update({
      root: input.root,
      id: input.id,
      patch: {
        ...(input.detail === undefined ? {} : { body: text(input.detail, "detail") }),
        ...(input.status || input.confidence ? { tags: patchTags } : {}),
      },
    })
    return decode(updated)
  }

  export function isType(value: string): value is Type {
    return validType(value)
  }
}
