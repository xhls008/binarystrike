import path from "path"
import { createHash } from "crypto"
import { mkdir, realpath } from "fs/promises"
import { check as checkScope } from "./scope.js"

export type Parsed = {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
}

function safe(input: string) {
  return input.replace(/[^a-zA-Z0-9._-]/g, "_")
}

function inside(root: string, target: string) {
  const relative = path.relative(root, target)
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function parse(raw: string, scheme: "http" | "https"): Parsed {
  const [head, ...body] = raw.replace(/\r\n/g, "\n").split("\n\n")
  const lines = (head ?? "").split("\n")
  const match = /^([A-Z]+)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i.exec(lines[0]?.trim() ?? "")
  if (!match) throw new Error("Invalid raw HTTP request")

  const headers = Object.fromEntries(
    lines
      .slice(1)
      .map((line) => {
        const at = line.indexOf(":")
        return at === -1 ? undefined : ([line.slice(0, at).trim(), line.slice(at + 1).trim()] as const)
      })
      .filter((line): line is readonly [string, string] => !!line),
  )
  const host = headers.Host ?? headers.host
  const url = new URL(match[2], host ? `${scheme}://${host}` : undefined)
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only HTTP and HTTPS retests are allowed")

  return {
    method: match[1].toUpperCase(),
    url: url.toString(),
    headers,
    body: body.join("\n\n") || undefined,
  }
}

export namespace Retest {
  export function parseRequest(raw: string, scheme: "http" | "https" = "https") {
    return parse(raw, scheme)
  }

  export type Result = {
    request_id: string
    url: string
    status: number
    changed: boolean
    baseline_status?: number
    evidence: string
    request: string
    response: string
  }

  export async function run(input: {
    root: string
    raw_request: string
    scheme?: "http" | "https"
    baseline_status?: number
    scope_items?: readonly string[]
    output_dir?: string
    signal?: AbortSignal
  }): Promise<Result> {
    const parsed = parse(input.raw_request, input.scheme ?? "https")
    if (input.scope_items?.length) {
      const scope = checkScope(parsed.url, input.scope_items)
      if (!scope.in_scope) throw new Error(`Retest target is out of scope: ${scope.target}`)
    }
    const id = "req_" + createHash("sha256").update(input.raw_request).digest("hex").slice(0, 16)
    const dir = input.output_dir
      ? path.resolve(input.root, input.output_dir)
      : path.join(input.root, ".binarystrike", "reports", "retests", safe(id))
    if (!inside(input.root, dir)) throw new Error(`Retest output must stay inside ${input.root}`)

    const headers = Object.fromEntries(
      Object.entries(parsed.headers).filter(([key]) => !["content-length", "connection"].includes(key.toLowerCase())),
    )
    const signal = AbortSignal.any([input.signal ?? new AbortController().signal, AbortSignal.timeout(30_000)])
    const response = await fetch(parsed.url, {
      method: parsed.method,
      headers,
      body: ["GET", "HEAD"].includes(parsed.method) ? undefined : parsed.body,
      signal,
      redirect: "manual",
    })
    const body = await response.text()
    await mkdir(dir, { recursive: true })
    if (!inside(input.root, await realpath(dir))) throw new Error(`Retest output must stay inside ${input.root}`)

    const result: Result = {
      request_id: id,
      url: parsed.url,
      status: response.status,
      changed: input.baseline_status !== undefined && input.baseline_status !== response.status,
      baseline_status: input.baseline_status,
      evidence: path.join(dir, "retest.json"),
      request: path.join(dir, "request.http"),
      response: path.join(dir, "response.txt"),
    }

    await Promise.all([
      Bun.write(result.request, input.raw_request),
      Bun.write(result.response, body),
      Bun.write(
        result.evidence,
        JSON.stringify(
          {
            ...result,
            response_headers: Object.fromEntries(response.headers.entries()),
            response_size: new TextEncoder().encode(body).length,
            time: Date.now(),
          },
          null,
          2,
        ),
      ),
    ])

    return result
  }
}
