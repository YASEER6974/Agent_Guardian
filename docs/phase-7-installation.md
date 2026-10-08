# Phase 7 installation and client setup

Agent Guardian has two cooperating parts:

- the **npm CLI/proxy**, which must be the MCP process launched by the AI client;
- the optional **VS Code extension**, which supplies configuration, live evidence, and exact one-time approval UI.

Only MCP servers routed through the proxy are protected. The controlled Browser Guardian is a separate Playwright harness; Agent Guardian does not silently intercept a user's ordinary browser or private tools built into an AI provider.

## 1. Install from this repository

Requirements: Node.js 20 or later and npm.

```powershell
npm install
npm run build
npm run pack:check
npm pack
npm install --global .\mcp-guardian-1.0.0.tgz
agent-guardian --help
```

Until the package is published to the npm registry, the generated `.tgz` is the reproducible local installation artifact. Do not run `npm publish` without the repository owner's approval and an agreed package name/publisher.

## 2. Configure the real downstream MCP server

This example routes the official-style “everything” test server behind Guardian:

```powershell
agent-guardian config add-server --name everything --command npx --args-json '["-y","@modelcontextprotocol/server-everything"]'
agent-guardian config show
```

Replace the name, command, and argument array with the MCP server you actually want to protect. On Windows PowerShell, single quotes around the JSON array prevent PowerShell from consuming its double quotes. For external Streamable HTTP endpoints, use `config add-server --name docs --url https://your-server.example/mcp`. In VS Code, **MCP Guardian: Add External MCP Server** performs this setup interactively. See [remote setup](remote-mcp-setup.md) for authentication, workspace routing and a real Microsoft Learn test.

Guardian stores local configuration and audit data under `%USERPROFILE%\.mcp-guardian` by default. Set `MCP_GUARDIAN_STORAGE_PATH` on both the proxy and extension-side workflow only when an isolated store is required.

## 3. Configure an MCP client

The examples assume the package was installed globally, so `agent-guardian` is on `PATH`.

### VS Code

Create `.vscode/mcp.json` in the workspace:

```json
{
  "servers": {
    "agent-guardian": {
      "type": "stdio",
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

Run **MCP: List Servers**, start `agent-guardian`, and inspect its output if startup fails. Current VS Code MCP configuration is documented at <https://code.visualstudio.com/docs/agent-customization/mcp-servers>.

On VS Code versions supporting MCP server providers, the Guardian extension also contributes an `agent-guardian` server automatically when the open workspace does not already configure one. This works in an empty Extension Development Host too. Its executable, storage directory, port, and explicit settings file come from the active extension, so no separate manual server entry is needed there. Reload the development host after building extension changes. The provider mechanism is documented at <https://code.visualstudio.com/api/extension-guides/ai/mcp#register-an-mcp-server-in-your-extension>.

### Cursor

Create `.cursor/mcp.json` in the project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

Cursor's current locations and schema are documented at <https://docs.cursor.com/context/model-context-protocol>.

### Claude Desktop

On Windows, edit `%APPDATA%\Claude\claude_desktop_config.json` and restart Claude Desktop:

```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

Anthropic's current local-server installation guidance is at <https://support.anthropic.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop>.

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

VS Code's current discovery reference also records this Windsurf configuration location: <https://code.visualstudio.com/docs/agents/reference/mcp-configuration#_automatic-mcp-server-discovery>.

### Generic stdio MCP client

Configure the executable `agent-guardian` with one argument, `proxy`. Guardian speaks newline-delimited JSON-RPC over standard input/output and starts the configured downstream servers itself. Do not configure the same downstream server directly alongside Guardian, because the agent could then bypass the proxy.

## 4. Install or debug the VS Code extension

For development:

1. Open this repository in VS Code.
2. Run `npm install` and `npm run compile`.
3. Press `F5` and choose **Extension Development Host**.
4. In the new window, select the shield icon labelled **MCP Guardian**.
5. Configure `mcp-guardian.sessionIntent`, `allowedCapabilities`, `trustedDestinations`, and `servers` in Settings.
6. Start the MCP server from the client's MCP configuration. The dashboard should change from **SHIELD IDLE** to **SHIELD ACTIVE**.

To create a VSIX for team installation:

```powershell
npx --yes @vscode/vsce package
code --install-extension .\mcp-guardian-1.0.0.vsix
```

The extension and proxy communicate on localhost port `1337` by default. `ASK` decisions fail closed if no approval UI connects before the configured timeout. `ALLOW` and deterministic `BLOCK` decisions still work without the extension.

## 5. Verify the installation

```powershell
npm test
npm run demo
npm run evaluate
```

- `npm test` validates the security/runtime behavior.
- `npm run demo` runs the malicious and benign presentation twins.
- `npm run evaluate` reproduces the Phase 6 corpus and ablations.

For the narrated classroom flow, use [`../demo/README.md`](../demo/README.md).

## Troubleshooting

- **Client cannot find `agent-guardian`:** use the absolute path to `dist/cli.js` with `node`, or reinstall the tarball globally.
- **No downstream tools appear:** run `agent-guardian config show` and inspect the MCP client output log.
- **Approval immediately fails or expires:** start the VS Code extension dashboard before the client invokes the tool.
- **Dashboard stays idle:** open the repository in the Extension Development Host and start the MCP server. Match `mcp-guardian.wsPort` with `MCP_GUARDIAN_WS_PORT` in the MCP launch configuration (the local development setup uses `1338`). The dashboard displays its connection port; the MCP log must say `Connected to VS Code extension on port ...`. Development environment overrides take precedence over extension setting defaults. Only one Guardian extension host can own that port.
- **After moving the repository:** update any absolute storage and filesystem-server paths in `.vscode/settings.json`. The extension and proxy must use the same runtime directory. Set `MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH` in the development launch environment to load the same configuration even if the development window opens without a folder.

In development mode, Guardian also loads `.vscode/settings.json` from its source directory when no explicit workspace-settings environment path is supplied. This keeps a restored, empty development window on the project's port and configuration instead of silently using the global defaults.
- **Browser demo lacks Chromium:** run `npx playwright install chromium`.
