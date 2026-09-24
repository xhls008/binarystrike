import { describe, expect, test } from "bun:test"
import { check, match } from "../src/scope.js"

describe("Scope", () => {
  test("matches exact hosts, wildcard domains, and IPv4 CIDRs", () => {
    expect(match("https://api.example.test/orders", "api.example.test").matches).toBe(true)
    expect(match("child.example.test", "*.example.test").matches).toBe(true)
    expect(match("10.2.3.4", "10.2.0.0/16").matches).toBe(true)
    expect(match("10.3.3.4", "10.2.0.0/16").matches).toBe(false)
  })

  test("returns structured details and denies an unmatched target", () => {
    const result = check("https://outside.test", ["*.example.test", "192.0.2.0/24"])
    expect(result.in_scope).toBe(false)
    expect(result.target).toBe("outside.test")
    expect(result.results).toHaveLength(2)
  })
})
