import { describe, expect, test } from "bun:test"
import { CloudPlan } from "../src/cloud.js"

describe("CloudPlan", () => {
  test("returns a read-only Kubernetes inventory plan without executing it", () => {
    const plan = CloudPlan.plan({ provider: "kubernetes", scope: "cluster:staging" })
    expect(plan.provider).toBe("kubernetes")
    expect(plan.scope).toBe("cluster:staging")
    expect(plan.steps.length).toBeGreaterThan(3)
    expect(plan.steps.every((step) => step.read_only)).toBe(true)
    expect(plan.steps.some((step) => step.command.includes("kubectl auth can-i"))).toBe(true)
    expect(plan.safety.join(" ")).toContain("never invokes kubectl")
  })

  test("filters a provider plan by focus and rejects unknown focus", () => {
    const plan = CloudPlan.plan({ provider: "aws", focus: "logging" })
    expect(plan.steps).toHaveLength(1)
    expect(plan.steps[0]?.id).toBe("logging")
    expect(() => CloudPlan.plan({ provider: "azure", focus: "secrets" })).toThrow("Unknown azure")
  })
})
