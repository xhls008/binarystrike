import { commands, env, Uri, ViewColumn, window, workspace } from "vscode"
import type { ExtensionContext, Terminal } from "vscode"

function quoteCommand(value: string) {
  if (/^[a-zA-Z0-9_./\\:-]+$/.test(value)) return value
  if (process.platform === "win32") return `"${value.replaceAll('"', '\\\"')}"`
  return `'${value.replaceAll("'", "'\\\\''")}'`
}

export function activate(context: ExtensionContext) {
  const terminals = new Map<Terminal, string>()

  async function open(fresh: boolean) {
    if (!workspace.isTrusted) {
      await window.showWarningMessage("Trust this workspace before launching BinStrike.")
      return
    }
    const editor = window.activeTextEditor
    const folder = (editor && workspace.getWorkspaceFolder(editor.document.uri)) ??
      (workspace.workspaceFolders?.length === 1 ? workspace.workspaceFolders[0] :
        await window.showWorkspaceFolderPick({ placeHolder: "Choose a workspace for BinStrike" }))
    if (!folder) return
    const existing = [...terminals].find(([terminal, directory]) =>
      directory === folder.uri.toString() && terminal.exitStatus === undefined)?.[0]
    if (existing && !fresh) {
      existing.show()
      return
    }
    const terminal = window.createTerminal({
      name: "BinStrike",
      cwd: folder.uri,
      env: { OPENCODE_CALLER: "vscode" },
      iconPath: {
        light: Uri.joinPath(context.extensionUri, "images/button-dark.svg"),
        dark: Uri.joinPath(context.extensionUri, "images/button-light.svg"),
      },
      location: { viewColumn: ViewColumn.Beside },
    })
    terminals.set(terminal, folder.uri.toString())
    terminal.show()
    terminal.sendText(`${quoteCommand(workspace.getConfiguration("binstrike").get<string>("cliPath", "binstrike"))}`, true)
  }

  context.subscriptions.push(
    commands.registerCommand("binstrike.openTerminal", () => open(false)),
    commands.registerCommand("binstrike.openNewTerminal", () => open(true)),
    commands.registerCommand("binstrike.copyReference", async () => {
      const editor = window.activeTextEditor
      if (!editor || !workspace.getWorkspaceFolder(editor.document.uri)) return
      const selection = editor.selection
      const start = selection.start.line + 1
      const end = selection.end.line + (selection.end.character === 0 ? 0 : 1)
      const lines = selection.isEmpty ? "" : end <= start ? `#L${start}` : `#L${start}-${end}`
      await env.clipboard.writeText(`@${workspace.asRelativePath(editor.document.uri, false)}${lines}`)
      window.setStatusBarMessage("BinStrike file reference copied; paste it into the prompt to review.", 3000)
    }),
    window.onDidCloseTerminal((terminal) => { terminals.delete(terminal) }),
  )
}
