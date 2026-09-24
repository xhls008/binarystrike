import { describe, expect, test } from "bun:test"
import { PlatformPlan } from "../src/platform.js"

describe("PlatformPlan", () => {
  test("plans eBPF posture inventory without attaching probes", () => {
    const plan = PlatformPlan.plan({ platform: "linux-ebpf", scope: "lab:linux" })
    expect(plan.platform).toBe("linux-ebpf")
    expect(plan.steps.every((step) => step.read_only)).toBe(true)
    expect(plan.steps.some((step) => step.command.includes("bpftool prog show"))).toBe(true)
    expect(plan.safety.join(" ")).toContain("never loads")
  })

  test("filters CI/CD plans and rejects unknown focus", () => {
    const plan = PlatformPlan.plan({ platform: "cicd", focus: "runner" })
    expect(plan.steps).toHaveLength(1)
    expect(plan.steps[0]?.id).toBe("runner")
    expect(() => PlatformPlan.plan({ platform: "windows", focus: "credential" })).toThrow("Unknown windows")
  })
})
