import { ComponentProps } from "solid-js"

const Glyph = () => {
  return (
    <g>
      <path
        d="M112 160H64M112 224H64M112 288H64M112 352H64M448 160H400M448 224H400M448 288H400M448 352H400M160 112V64M224 112V64M288 112V64M352 112V64M160 448V400M224 448V400M288 448V400M352 448V400"
        stroke="var(--icon-strong-base)"
        stroke-opacity="0.28"
        stroke-width="18"
        stroke-linecap="round"
      />
      <rect
        x="112"
        y="112"
        width="288"
        height="288"
        rx="42"
        fill="var(--icon-strong-base)"
        fill-opacity="0.08"
        stroke="var(--icon-strong-base)"
        stroke-opacity="0.9"
        stroke-width="18"
      />
      <path
        d="M154 184H122M154 256H122M154 328H122M390 184H358M390 256H358M390 328H358"
        stroke="#58D9FF"
        stroke-opacity="0.78"
        stroke-width="10"
        stroke-linecap="round"
      />
      <path
        d="M184 156H216V356H184V156ZM216 156H308V188H216V156ZM216 240H318V272H216V240ZM216 324H318V356H216V324ZM296 188H328V240H296V188ZM306 272H338V324H306V272Z"
        fill="var(--icon-strong-base)"
      />
      <path d="M344 132L174 380" stroke="#2FFFA2" stroke-width="18" stroke-linecap="round" />
      <path d="M348 132H292M174 380H230" stroke="#2FFFA2" stroke-width="18" stroke-linecap="round" />
      <rect x="146" y="146" width="18" height="18" fill="#58D9FF" />
      <rect x="348" y="348" width="18" height="18" fill="#2FFFA2" />
    </g>
  )
}

export const Mark = (props: { class?: string }) => {
  return (
    <svg
      data-component="logo-mark"
      classList={{ [props.class ?? ""]: !!props.class }}
      viewBox="0 0 512 512"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <Glyph />
    </svg>
  )
}

export const Splash = (props: Pick<ComponentProps<"svg">, "ref" | "class">) => {
  return (
    <svg
      ref={props.ref}
      data-component="logo-splash"
      classList={{ [props.class ?? ""]: !!props.class }}
      viewBox="0 0 400 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <g transform="translate(164, 6) scale(0.14)">
        <Glyph />
      </g>
      <text
        x="200"
        y="106"
        text-anchor="middle"
        font-family="ui-monospace, SFMono-Regular, Consolas, monospace"
        font-size="31"
        font-weight="800"
        letter-spacing="0"
        fill="var(--icon-strong-base)"
      >
        BinaryStrike
      </text>
    </svg>
  )
}

export const Logo = (props: { class?: string }) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 400 160"
      fill="none"
      classList={{ [props.class ?? ""]: !!props.class }}
    >
      <g transform="translate(152, 4) scale(0.19)">
        <Glyph />
      </g>
      <text
        x="200"
        y="143"
        text-anchor="middle"
        font-family="ui-monospace, SFMono-Regular, Consolas, monospace"
        font-size="32"
        font-weight="800"
        letter-spacing="0"
        fill="var(--icon-strong-base)"
      >
        BinaryStrike
      </text>
    </svg>
  )
}
