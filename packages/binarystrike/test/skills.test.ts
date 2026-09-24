import { describe, expect, test } from "bun:test"
import path from "path"

const root = path.resolve(import.meta.dir, "../../..")
const skills = [
  "recon-methodology",
  "attack-idor-automation",
  "attack-ssrf",
  "attack-jwt",
  "attack-cors",
  "attack-open-redirect",
  "attack-request-smuggling",
  "attack-xxe",
  "attack-ssti",
]

describe("V2 security skills", () => {
  test("keeps selected V1 methodology skills as parseable project-local skills with agent permissions", async () => {
    const agent = await Bun.file(path.join(root, ".opencode", "agent", "binary-security.md")).text()
    for (const name of skills) {
      const file = path.join(root, ".opencode", "skills", name, "SKILL.md")
      const content = await Bun.file(file).text()
      expect(content.startsWith("---\n")).toBe(true)
      expect(content).toContain(`name: ${name}`)
      expect(content).toContain("## BinaryStrike V2 Boundary")
      expect(content).toContain("scope_check")
      expect(agent).toContain(`resource: "${name}"`)
    }
  })
})
