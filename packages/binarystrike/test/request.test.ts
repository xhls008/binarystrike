import { describe, expect, test } from "bun:test"
import { Request } from "../src/request.js"
import { tmpdir } from "./fixture.js"

const raw = "POST /orders?id=1 HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n\r\n{\"id\":1}"

describe("Request", () => {
  test("stores project-local HTTP observations with structural deduplication", async () => {
    await using dir = await tmpdir()
    const first = await Request.record({
      root: dir.path,
      raw_request: raw,
      scope_items: ["*.example.test"],
      source: "proxy",
      response: { status: 403, headers: { "content-type": "application/json" }, body: "blocked" },
    })
    const duplicate = await Request.record({ root: dir.path, raw_request: raw, response: { status: 200, body: "different" } })
    const safe = await Request.read({ root: dir.path })
    const full = await Request.read({ root: dir.path, id: first.entry.id, include_body: true })

    expect(first.duplicate).toBe(false)
    expect(duplicate.duplicate).toBe(true)
    expect(safe[0]).not.toHaveProperty("raw_request")
    expect(full[0]).toMatchObject({ method: "POST", host: "api.example.test", response_status: 403, response_body: "blocked" })
    expect(await Request.context(dir.path)).toContain("Recent HTTP Observations")
  })

  test("enforces optional scope before recording and supports lifecycle updates", async () => {
    await using dir = await tmpdir()
    await expect(Request.record({ root: dir.path, raw_request: raw, scope_items: ["other.example.test"] })).rejects.toThrow(
      "out of scope",
    )
    await expect(Request.record({ root: dir.path, raw_request: raw, response: { status: 700 } })).rejects.toThrow(
      "between 100 and 599",
    )
    const created = await Request.record({ root: dir.path, raw_request: raw })
    const updated = await Request.update({ root: dir.path, id: created.entry.id, status: "processing" })
    expect(updated.status).toBe("processing")
    expect(await Request.history(dir.path)).toHaveLength(2)
  })

  test("normalizes browser observations into the passive request ledger", async () => {
    await using dir = await tmpdir()
    const result = await Request.recordBrowser({
      root: dir.path,
      url: "https://api.example.test/orders/1?view=full",
      method: "get",
      request_headers: { "x-test": "browser" },
      response: { status: 200, body: '{"id":1}' },
      scope_items: ["*.example.test"],
    })
    expect(result.duplicate).toBe(false)
    expect(result.entry).toMatchObject({ method: "GET", host: "api.example.test", source: "browser" })
    expect(result.entry.tags).toContain("browser")
    expect(result.entry.response_status).toBe(200)
    expect((await Request.read({ root: dir.path, include_body: true }))[0]?.raw_request).toContain(
      "GET /orders/1?view=full HTTP/1.1",
    )
  })

  test("rejects browser header line injection", async () => {
    await using dir = await tmpdir()
    await expect(
      Request.recordBrowser({
        root: dir.path,
        url: "https://api.example.test/",
        request_headers: { "x-bad": "ok\r\nX-Injected: yes" },
      }),
    ).rejects.toThrow("line break")
  })
})
