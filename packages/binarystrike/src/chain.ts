import { Coverage } from "./coverage.js"
import { Intel } from "./intel.js"

/**
 * Read-only chain detection over the V2 blackboard projection.
 *
 * Unlike V1 this module has no chain table and never schedules a worker. A
 * candidate is a view over current Intel and VRT facts; the agent decides
 * whether to write an Intent for the suggested test.
 */
export namespace Chain {
  export type Pattern =
    | "credential_endpoint"
    | "info_disclosure_ssrf"
    | "redirect_oauth"
    | "idor_data_leak"
    | "xss_csrf"
    | "ssti_rce"
    | "race_condition_business"
    | "custom"

  export type Candidate = {
    id: string
    pattern: Pattern
    intel_ids: string[]
    titles: string[]
    assets: string[]
    impact: string
    severity: "critical" | "high" | "medium"
    confidence: number
    testing_plan: string
  }

  const oauth = /\b(oauth|authorize|callback|redirect_uri|token|sso|saml|openid)\b/i
  const stateChange = /\b(POST|PUT|DELETE|PATCH|create|update|delete|transfer|payment|invite|admin)\b/i
  const userData = /\b(user|profile|account|email|phone|address|personal|private|settings)\b/i
  const payment = /\b(payment|transfer|order|checkout|cart|purchase|balance|credit|withdraw|deposit)\b/i

  function sameAsset(a: Intel.Entry, b: Intel.Entry) {
    const left = a.asset.toLowerCase()
    const right = b.asset.toLowerCase()
    if (left === right) return true
    const domain = (value: string) => value.split(".").slice(-2).join(".")
    return domain(left) === domain(right)
  }

  function text(entry: Intel.Entry) {
    return `${entry.title} ${entry.detail} ${entry.tags.join(" ")}`
  }

  function key(pattern: Pattern, entries: readonly Intel.Entry[]) {
    return `chain_${pattern}_${entries.map((entry) => entry.id).sort().join("_")}`
  }

  export async function detect(root: string) {
    const [entries, checks] = await Promise.all([Intel.read({ root }), Coverage.query({ root, limit: 10_000 })])
    const byId = new Map(entries.map((entry) => [entry.id, entry]))
    const vulnerable = (entry: Intel.Entry, category: string) =>
      checks.some(
        (check) => check.intel_id === entry.id && check.verdict === "tested_vulnerable" && check.class.toLowerCase().includes(category),
      )
    const output: Candidate[] = []
    const seen = new Set<string>()
    const add = (
      pattern: Pattern,
      related: Intel.Entry[],
      impact: string,
      severity: Candidate["severity"],
      confidence: number,
      testing_plan: string,
    ) => {
      const id = key(pattern, related)
      if (seen.has(id)) return
      seen.add(id)
      output.push({
        id,
        pattern,
        intel_ids: related.map((entry) => entry.id),
        titles: related.map((entry) => entry.title),
        assets: [...new Set(related.map((entry) => entry.asset))],
        impact,
        severity,
        confidence,
        testing_plan,
      })
    }

    const credentials = entries.filter((entry) => entry.type === "credential")
    const endpoints = entries.filter((entry) => entry.type === "endpoint")
    const services = entries.filter((entry) => ["configuration", "infrastructure"].includes(entry.type))
    for (const credential of credentials) {
      for (const endpoint of endpoints) {
        if (!sameAsset(credential, endpoint) || endpoint.severity === "info") continue
        add(
          "credential_endpoint",
          [credential, endpoint],
          "ACCOUNT_TAKEOVER",
          "critical",
          credential.status === "exploited" || credential.confidence === "confirmed" ? 85 : 65,
          `Use "${credential.title}" to authenticate against "${endpoint.title}" in an authorized test.`,
        )
      }
    }
    for (const info of services) {
      for (const endpoint of endpoints) {
        if (!sameAsset(info, endpoint) || !vulnerable(endpoint, "ssrf")) continue
        add(
          "info_disclosure_ssrf",
          [info, endpoint],
          "SSRF_TO_INTERNAL",
          "high",
          90,
          `Use the disclosed internal target from "${info.title}" through "${endpoint.title}".`,
        )
      }
    }
    for (const entry of entries) {
      if (!vulnerable(entry, "redirect")) continue
      for (const endpoint of entries) {
        if (entry.id === endpoint.id || !sameAsset(entry, endpoint) || !oauth.test(text(endpoint))) continue
        add(
          "redirect_oauth",
          [entry, endpoint],
          "TOKEN_THEFT",
          "critical",
          80,
          `Test whether the redirect in "${entry.title}" can capture an OAuth token from "${endpoint.title}".`,
        )
      }
    }
    for (const entry of entries) {
      if (!vulnerable(entry, "idor")) continue
      for (const endpoint of endpoints) {
        if (entry.id === endpoint.id || !sameAsset(entry, endpoint) || !userData.test(text(endpoint))) continue
        add(
          "idor_data_leak",
          [entry, endpoint],
          "MASS_DATA_LEAK",
          "critical",
          85,
          `Enumerate authorized object identifiers from "${entry.title}" against "${endpoint.title}".`,
        )
      }
    }
    for (const entry of entries) {
      if (!vulnerable(entry, "xss")) continue
      for (const endpoint of endpoints) {
        if (entry.id === endpoint.id || !sameAsset(entry, endpoint) || !stateChange.test(text(endpoint))) continue
        add(
          "xss_csrf",
          [entry, endpoint],
          "CSRF_BYPASS",
          "high",
          75,
          `Test whether "${entry.title}" can trigger state-changing requests at "${endpoint.title}".`,
        )
      }
    }
    for (const entry of entries) {
      if (vulnerable(entry, "ssti"))
        add("ssti_rce", [entry], "RCE", "critical", 85, `Test template gadget paths from "${entry.title}" to code execution.`)
      if (!vulnerable(entry, "race")) continue
      for (const endpoint of endpoints) {
        if (entry.id === endpoint.id || !sameAsset(entry, endpoint) || !payment.test(text(endpoint))) continue
        add(
          "race_condition_business",
          [entry, endpoint],
          "FINANCIAL_IMPACT",
          "critical",
          80,
          `Test concurrency around the financial operation "${endpoint.title}".`,
        )
      }
    }
    for (const entry of entries) {
      for (const related of entry.related_ids.map((id) => byId.get(id)).filter((item): item is Intel.Entry => Boolean(item))) {
        add("custom", [entry, related], "ESCALATION", "medium", 60, `${entry.title} may chain with ${related.title}.`)
      }
    }
    return output.sort((a, b) => b.confidence - a.confidence)
  }

  export function format(chains: readonly Candidate[]) {
    if (!chains.length) return undefined
    return [
      `## Chain Opportunities (${chains.length})`,
      ...chains.slice(0, 10).flatMap((chain) => [
        `- [${chain.severity.toUpperCase()} / ${chain.confidence}%] ${chain.pattern}: ${chain.titles.join(" + ")} → ${chain.impact}`,
        `  Test: ${chain.testing_plan}`,
      ]),
    ].join("\n")
  }
}
