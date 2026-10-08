# Guarding remote MCP servers

The AI client starts the local Guardian proxy. Guardian connects to remote Streamable HTTP MCP endpoints. Both JSON and SSE responses use the same metadata inspection, approved fingerprints, policy gates, output inspection and audit log as the local transport.

The current development setup uses Microsoft Learn at `https://learn.microsoft.com/api/mcp`. This public endpoint supplies Microsoft documentation tools. Source: https://learn.microsoft.com/en-us/training/support/mcp-developer-reference

## VS Code

1. Build with `npm run build` and reload the Extension Development Host.
2. Use **MCP Guardian: Add External MCP Server** (or **Add External MCP** under Servers Setup).
3. Choose **Remote HTTP MCP**, enter a name and the remote `/mcp` URL, and use `{}` for public endpoints.
4. Start `agent-guardian` from **MCP: List Servers**. Enable its tools in Agent chat.
5. For existing direct workspace MCP entries, run **MCP Guardian: Guard Workspace MCP Servers**. It imports their configuration and saves a backup before replacing the workspace list with the Guardian proxy. Restart any previously running direct entries.

Paste this prompt for the configured Microsoft Learn server:

```text
Use only Agent Guardian's microsoft-learn__microsoft_docs_search tool to search for Azure Functions Node.js runtime documentation. Summarize the returned information and include the documentation links. Do not use built-in web search, the browser, or terminal commands.
```

If Guardian asks, choose **Approve Once** for that documentation search. The timeline should show the remote tool name and an ALLOW result. The endpoint is configured inside Guardian, not as a separate direct HTTP server in VS Code.

The Security Rules tab updates after discovery and before remote calls, and completed approvals disappear from Pending Alerts. If the view was hidden or restored, **MCP Guardian: Refresh Dashboard** requests a fresh snapshot from the running proxy. After rebuilding the extension, reload its development window and restart the MCP server to load the updated code. The proxy owns runtime persistence; dashboard snapshots do not rewrite its database.

## CLI

```powershell
node dist/cli.js config add-server --name microsoft-learn --url https://learn.microsoft.com/api/mcp --workspace-settings .vscode/settings.json --storage .mcp-guardian/runtime
```

For authenticated servers, set a local environment variable before starting the IDE/proxy and configure a header reference, for example `"headers": {"Authorization": "Bearer ${env:MY_MCP_TOKEN}"}`. Guardian resolves it only at connection time and masks headers in CLI config output. This version supports static headers and environment references; interactive OAuth authorization and the legacy two-endpoint SSE transport are not implemented.

## Checks and limits

`node --test test/remote-http.test.js` runs controlled HTTP/SSE tests for inspection, header/session handling, concurrency, pagination, poisoned descriptions, a rug pull before a call, poisoned results, authentication failure and timeouts.

`node test/remote-live.smoke.js` makes one real Microsoft Learn search through Guardian with an isolated test database. It does not change the workspace's manual-approval settings.

Rejected and changed descriptions are withheld from the agent's tool list. For remote servers, Guardian fetches fresh definitions before tool calls; a changed definition requires explicit re-baselining. This does not replace the still-unimplemented 15-day scheduled recheck. Metadata inspection cannot establish that a remote backend's internal implementation is harmless.

Only configurations routed through Guardian are protected. The workspace-routing command covers the selected workspace configuration; it cannot intercept private IDE tools, global server entries, other applications or servers added directly later. Add future external servers using Guardian's command, or run the routing command again.
