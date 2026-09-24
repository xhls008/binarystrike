import { describe, expect, test } from "bun:test"
import { Chain } from "../src/chain.js"
import { Intel } from "../src/intel.js"
import { tmpdir } from "./fixture.js"

describe("Chain", () => {
  test("derives credential-to-endpoint paths without persisting scheduler state", async () => {
    await using dir = await tmpdir()
    const credential = await Intel.record({
      root: dir.path,
      type: "credential",
      title: "Recovered service credential",
      asset: "api.example.test",
      confidence: "high",
      status: "tested",
    })
    const endpoint = await Intel.record({
      root: dir.path,
      type: "endpoint",
      title: "Admin orders API",
      asset: "api.example.test",
      severity: "high",
      confidence: "high",
    })

    const chains = await Chain.detect(dir.path)
    expect(chains).toHaveLength(1)
    expect(chains[0]).toMatchObject({
      pattern: "credential_endpoint",
      intel_ids: [credential.entry.id, endpoint.entry.id],
      impact: "ACCOUNT_TAKEOVER",
    })
    expect(Chain.format(chains)).toContain("Chain Opportunities")
  })

  test("preserves explicit related-entry paths as custom candidates", async () => {
    await using dir = await tmpdir()
    const first = await Intel.record({
      root: dir.path,
      type: "configuration",
      title: "Debug interface exposed",
      asset: "device.local",
      confidence: "high",
    })
    const second = await Intel.record({
      root: dir.path,
      type: "sensitive_data",
      title: "Sensitive key in debug output",
      asset: "device.local",
      confidence: "high",
      related_ids: [first.entry.id],
    })

    const chains = await Chain.detect(dir.path)
    expect(chains.some((chain) => chain.pattern === "custom" && chain.intel_ids.includes(second.entry.id))).toBe(true)
  })
})
