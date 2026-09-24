import { RGBA } from "@opentui/core"
import { createMemo, For } from "solid-js"
import { useTheme } from "../context/theme"
import { logo } from "../logo"

function lerp(a: RGBA, b: RGBA, t: number) {
  return RGBA.fromInts(
    Math.round((a.r + (b.r - a.r) * t) * 255),
    Math.round((a.g + (b.g - a.g) * t) * 255),
    Math.round((a.b + (b.b - a.b) * t) * 255),
  )
}

export function Logo() {
  const theme = useTheme()
  const stops = createMemo(() => [theme.hue.interactive[200], theme.hue.accent[200]])
  return (
    <box>
      <For each={logo}>
        {(line, index) => {
          const color = createMemo(() => {
            const t = index() / Math.max(1, logo.length - 1)
            const colors = stops()
            return lerp(colors[0], colors[1], t)
          })
          return (
            <box flexDirection="row">
              <text fg={color()} selectable={false}>
                {line}
              </text>
            </box>
          )
        }}
      </For>
    </box>
  )
}
