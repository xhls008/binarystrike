# BinStrike for VS Code

Terminal-based integration for BinStrike V2 (not a webview/chat sidebar).
It launches the same `binstrike` CLI and uses its existing model configuration.
This project currently defaults to the local OpenAI-compatible endpoint at
`http://127.0.0.1:8099/v1`; no credentials are stored by the extension.

## Install locally

First install the CLI from the V2 repository (Bun and repository dependencies required):

```sh
mkdir -p ~/.local/bin
ln -s "$PWD/script/binstrike" ~/.local/bin/binstrike
binstrike --help
```

Then build the extension:

```sh
cd sdks/vscode
bun install
bun run vsix
code --install-extension dist/binstrike.vsix
```

Alternatively, use **Extensions: Install from VSIX** in VS Code. This package is
for local installation; it has not been published to a marketplace.

## Usage

- **BinStrike: Open Terminal** (`Ctrl+Esc` / `Cmd+Esc`): launch or focus the current workspace's CLI.
- **BinStrike: New Terminal**: start another session.
- **BinStrike: Copy File Reference**: copy the current file/selected line reference for manual pasting. Nothing is automatically submitted or executed.
- `binstrike.cliPath`: executable path, not a shell command. Use the absolute path to `script/binstrike` if VS Code cannot find the command.

Trust the workspace before launching. Multi-root workspaces use the active
file's folder, or ask you to select a folder. With Remote SSH/containers, install
both the extension and CLI on that remote host; localhost:8099 then means that host.

If launch fails, inspect the terminal error and check `binstrike.cliPath` and Bun.
No legacy `/tui/append-prompt` endpoint or extra unauthenticated server is used.
