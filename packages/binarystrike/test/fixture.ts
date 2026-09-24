import { mkdir, rm } from "fs/promises"
import os from "os"
import path from "path"

export async function tmpdir() {
  const dir = path.join(os.tmpdir(), `binarystrike-${crypto.randomUUID()}`)
  await mkdir(dir, { recursive: true })
  return {
    path: dir,
    async [Symbol.asyncDispose]() {
      await rm(dir, { recursive: true, force: true })
    },
  }
}
