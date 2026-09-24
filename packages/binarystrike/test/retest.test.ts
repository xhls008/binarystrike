import { describe, expect, test } from "bun:test"
import { tmpdir } from "./fixture.js"
import { Retest } from "../src/retest.js"

describe("Retest.run", () => {
  test("replays a raw request and writes evidence", async () => {
    await using dir = await tmpdir()
    const server = Bun.serve({
      port: 0,
      fetch() {
        return new Response("ok", { status: 201, headers: { "content-type": "text/plain" } })
      },
    })

    const result = await Retest.run({
      root: dir.path,
      raw_request: `GET /health HTTP/1.1\nHost: 127.0.0.1:${server.port}\n\n`,
      scheme: "http",
      baseline_status: 200,
      scope_items: ["127.0.0.1/32"],
    })

    expect(result.status).toBe(201)
    expect(result.changed).toBe(true)
    expect(result.request_id).toMatch(/^req_[0-9a-z]{16}$/)
    expect(result.evidence).toContain(".binarystrike")
    expect(await Bun.file(result.request).text()).toContain("GET /health HTTP/1.1")
    expect(await Bun.file(result.response).text()).toBe("ok")
    expect(await Bun.file(result.evidence).json()).toMatchObject({ status: 201 })

    server.stop(true)
  })

  test("rejects non-HTTP request targets", () => {
    expect(Retest.run({ root: "/", raw_request: "GET file:///etc/passwd HTTP/1.1\n\n" })).rejects.toThrow(
      "Only HTTP and HTTPS",
    )
  })

  test("rejects an out-of-scope target before fetching", () => {
    expect(
      Retest.run({
        root: "/",
        raw_request: "GET /health HTTP/1.1\nHost: outside.example.test\n\n",
        scheme: "https",
        scope_items: ["*.authorized.example.test"],
      }),
    ).rejects.toThrow("out of scope")
  })
})
