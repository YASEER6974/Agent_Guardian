# MCP Guardian completion and external deployment test

## What is protected

Guardian is a transport-independent security proxy, not a file antivirus. For
every configured external server, it inspects discovered tool descriptions and
schemas, fingerprints definitions, re-discovers metadata before a tool call,
checks capability/intent and data-flow policies, asks for approval when required,
inspects returned content and records the decision. File reads are only one test
of those gates. An ordinary permitted call should succeed, not raise an attack
alert just because an MCP server was used.

It protects **connections routed through it**, not every connection made by an
IDE. Private IDE tools, direct MCP entries and terminal/CLI fallbacks are outside
this proxy. Do not describe the shield as system-wide interception.

## Multi-client approval routing

Approvals are bound to the WebSocket connection that created the request, its
request ID, exact action fingerprint and expiry. A new client cannot steal an
older client's approval. The dashboard shows a submitted decision as waiting,
not ALLOW, until the original proxy publishes its authoritative log. Unrelated
snapshots do not erase pending requests and another proxy cannot acknowledge
them. Closing one client keeps remaining clients connected. The default manual
approval window is 120 seconds; deployments still require explicit policy.

The separate website source is in
[agent-guardian-test-website](https://github.com/YASEER6974/agent-guardian-test-website).
It is a private, independent Git repository; only the three static public assets
are deployment inputs. `node demo/deploy-test-website.js --deploy --team <verified-team-id>` is an explicitly
authorized, narrowly targeted scripted preview test through Guardian using an
isolated runtime policy/store, not the IDE's manual-approval configuration. Never
claim this script is a recorded Antigravity chat run. Team authorization is
checked before any remote write. Failed Vercel authorization must be corrected
by the human consent flow, not a CLI bypass.

## Definition review

Security Rules now distinguishes approved, first-seen, drifted and rejected
definitions. Expand the review section for saved/observed descriptions, hashes,
exact field differences, inspection completeness and evidence. Acceptance
requires a review checkbox and the exact observed hash. Rejected definitions,
incomplete inspections and definitions with findings cannot be accepted through
this shortcut. Refresh MCP tools after accepting a legitimate changed definition.

## Antigravity routing

Use **MCP Servers → Manage MCP Servers → View raw config** to find the file
actually used by your installed version. From the Guardian project folder:

The dashboard's **Guard Antigravity MCPs** button (or command **MCP Guardian:
Guard Antigravity MCP Servers**) opens a picker for that same config file. The
CLI alternative is:

```powershell
npm run build
node dist/cli.js config guard-antigravity --config "C:\path\from\View raw config\mcp_config.json" --workspace "C:\path\to\Agent_Guardian"
```

This backs up the client configuration, imports supported stdio and HTTP
(`serverUrl`) entries into workspace Guardian settings, and leaves only the
Guardian proxy in the client list. It preserves comments and unrelated fields.
Validation completes before mutation. Explicit OAuth, disabled-tool and other
unsupported client constraints cause an error, not a silent downgrade. Duplicate
names require manual resolution. Existing local workspace settings remain local;
credentials in an original config can also exist in its local backup. Never
commit these files. Stop old direct servers, reload the matching extension host,
and refresh Antigravity's MCP manager. Do not run multiple dashboard hosts on the
same port or allow two proxies to share one approval dashboard.

## Vercel test payload

The isolated website is in the sibling `Guardian_Test_Website` folder and its
separate repository. Its deployable assets are `index.html`, `receipt.html`, and
`style.css`. The earlier `demo/vercel/demo.html` draft is not part of the agent
repository or the hosted website. Do not deploy the entire Guardian
repository, handbook, runtime database or account secrets. Use a **new disposable
project**, preview target, no production domain changes and no paid upgrades.
Vercel's official endpoint is `https://mcp.vercel.com`. Its authenticated tools
require OAuth, and it maintains an approved-client list. Do not impersonate a
supported client or extract IDE OAuth tokens.

Vercel documents `mcp-remote` for Gemini clients. Guardian can inspect a stdio
bridge as a downstream server, and metadata is rechecked before calls for this
transport too. A pinned candidate configuration, not a proven live connection:

```json
{
  "name": "vercel",
  "command": "cmd",
  "args": ["/c", "npx", "-y", "mcp-remote@0.14.3", "https://mcp.vercel.com"]
}
```

Add this inside **Guardian's downstream settings**, not alongside Guardian in
Antigravity's MCP list. The bridge is third-party software, not part of Guardian;
review it before executing and complete any sign-in yourself. Authentication and
Vercel client approval must succeed before we claim deployment coverage. A
native Guardian OAuth implementation remains future work. Initial authorization
can exceed the usual discovery timeout; authenticate before the demonstration
instead of disabling fail-closed behavior.

### Test sequence

1. Discover tools: verify Vercel tools appear under Guardian, with stored
   fingerprints. Do not assume a deployment tool exists; inspect the actual list.
2. Read-only prompt: "Using only agent-guardian MCP tools, list my Vercel teams
   and projects. Do not use the CLI, browser or a direct Vercel connection."
3. Choose the disposable demo team/project explicitly. Use manual approvals.
   A read-only policy should refuse publishing. Deployment tools are categorized
   as WRITE_COMMUNICATION (external publication), not GENERAL. Grant that
   capability only for the intended demo session after reviewing the destination.
4. If an actual deployment MCP tool is available, ask: "Using only the Vercel
   tool exposed through agent-guardian, deploy only the three static website assets
   to the selected disposable project as a preview. Do not publish production,
   change domains, upload other repository files or fall back to terminal commands.
   If the MCP cannot deploy it, stop and explain the missing capability."
5. Approve the exact action in Guardian. Verify the provider's URL, preview target
   and returned status, plus the matching ALLOW log and uploaded-file scope.
6. Controlled fixture tests cover poisoned descriptions, changed definitions,
   harmful output, missing authentication and forbidden capabilities. Never
   inject malicious descriptions into someone else's live provider or deploy a
   destructive payload merely to test blocking.

A successful deployment is a functionality test. The controlled malicious and
benign twins plus blocked-side-effect assertions demonstrate security behavior.

The first live demo deployment is READY at
https://agent-guardian-test-website.vercel.app. Vercel marked this new project's
initial deployment as production, despite the omitted target in the request.
The script now explicitly requests staging for future writes and inspects the
actual returned target; never label the first deployment a preview. Existing
projects were not modified. The first deployment was a scripted Guardian MCP
test, not a prompt-driven Antigravity deployment.

## Remaining before calling MCP Guardian complete

- Native remote OAuth and elicitation support, or a verified authenticated bridge
  for each chosen provider. Current stdio/HTTP coverage is not universal protocol coverage.
- Reliable per-client session intent integration. An arbitrary typed chat prompt
  is not automatically observable by a standalone MCP proxy.
- Per-proxy approval routing if multiple IDEs run at once.
- Live provider-specific read/write tests and understandable exported decisions.
- Scheduled 15-day metadata rechecks (current checks happen on discovery/calls).
- Formalizing remote-write capabilities beyond the conservative publication
  category; tool-name classification is a heuristic, not a permission proof.

Sources: [Vercel MCP](https://vercel.com/docs/agent-resources/vercel-mcp),
[tools reference](https://vercel.com/docs/agent-resources/vercel-mcp/tools),
[mcp-remote source](https://github.com/punkpeye/mcp-remote).
