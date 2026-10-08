# Browser Guardian: agent-facing MCP integration

The first usable browser integration runs as a downstream MCP server. It reuses
the browser harness and policy engine; it does not install a universal browser
interceptor.

```text
IDE agent -> Agent Guardian MCP proxy -> Browser Guardian MCP -> isolated Chromium -> website
                       |                       |
                   MCP audit             browser audit -> Guardian dashboard
```

## What was verified

`npm run demo:browser-live` uses a scripted MCP client, not an IDE chat session.
It verifies the complete proxy/browser boundary, not just the detector functions:

1. The public deployed demo page is inspected and returned with `ALLOW`.
2. A synthetic `DEMO-ONLY` GET form reaches its static receipt. No database record is written.
3. A local poisoned copy of the separate site's HTML returns `BLOCK` with B1/R6.
   Hidden instructions and the sentinel never reach the agent in the tool result.
4. A follow-up form call is held by browser-to-MCP provenance policy, and the local
   receiver sees zero submissions. The offline approval interface fails closed.

The public website is not poisoned or redeployed by this test. Its source remains
in [the separate website repository](https://github.com/YASEER6974/agent-guardian-test-website).
The script uses isolated stores and a narrow scripted demo policy; it does not
turn off manual approvals or enable writes in the IDE's configuration.

Readable evidence is saved to `demo/output/browser-live/report.txt`, with browser
and MCP audits beside it. These runtime artifacts are local and must not be
committed with credentials or personal data.

## Local installation

From the Agent_Guardian repository in PowerShell:

```powershell
npm install
npx playwright install chromium
npm run build
node dist/cli.js config add-browser --workspace-settings .vscode/settings.json --allowed-origin https://agent-guardian-test-website.vercel.app
```

The command backs up settings, preserves existing servers and manual approval /
capability settings, and adds `browser` behind the existing Guardian proxy. By
default it exposes only `browser__web_read_page` and `browser__web_follow_link`.
This does not weaken the existing read-only Vercel policy.

Reload the Guardian extension host to load the rebuilt dashboard. In VS Code,
open Ctrl+Shift+P -> **MCP: List Servers** -> **agent-guardian** -> restart. In
Antigravity, open its MCP server management page and refresh/reconnect
**agent-guardian**. Confirm the browser-prefixed tools are present under Guardian.
Do not add Browser Guardian as an unguarded, direct IDE connection.
If you run the source in an Extension Development Host, restart that debug session
after building. Reloading an old installed VSIX does not install new extension
code; that installation must be rebuilt/reinstalled separately.

Use this prompt:

```text
Use only agent-guardian's browser__web_read_page tool to open
https://agent-guardian-test-website.vercel.app and summarize the page.
Do not use the built-in browser, web search, terminal, or another MCP server.
If Guardian asks for approval, wait. If content is withheld, report its decision
and rule IDs without trying another route. Do not submit any form.
```

Select Guardian's browser tools in the IDE tool picker. An agent needs the actual
tool connection, not just this prompt. Guardian cannot enforce that a host with
other enabled tools chooses this route; disable other browser/search paths for
the demonstration.

## Optional demo forms

`--allow-forms` additionally exposes `fill_field` and `submit_form`. `--trusted-origin`
can explicitly designate the controlled demo origin (it must also be allowed).
The outer MCP session must separately permit `WRITE_COMMUNICATION`; merely
exposing tools does not authorize them. Keep Vercel / other production write
capabilities restricted. The live verification script supplies a separate fixed
demo policy so you do not need to broaden your normal IDE policy.

These tools support synthetic demonstration data, not authenticated production
workflows. Password / token / credential-like fields require a capability that
the Browser MCP server does not grant. There is no evaluate-JavaScript, arbitrary
click, file-upload, purchase, download, or system-execution tool.

## Browser decisions

| Rule | Meaning | Result |
|---|---|---|
| B1 | Detected instruction/injection pattern in inspected website content | BLOCK; page content withheld |
| B2 | Page/frame/structured scan exceeded limits or could not be completed | BLOCK; page content withheld |
| B3 | Unapproved destination or refused redirect | BLOCK before following the request |
| R6 | Hidden content or untrusted browser influence | ASK; no execution without an embedding approval handler |
| R4 | Credential entry at an untrusted destination | BLOCK |
| R8 | Browser-derived content influences an external MCP write | ASK through the outer proxy |

Page content is checked before release and rechecked before field entry, link
following, or form submission. Held reports include rule IDs and detector reasons,
not raw hidden snippets. Browser records are hash chained in the shared store;
the extension watches that trace and updates even without another MCP log message.

## Deliberate limits and next work

- Only operator-configured HTTP(S) origins are allowed; adding an origin permits
  network access, not permission to obey instructions from it. No wildcard trust.
- Page JavaScript and service workers are disabled in Browser MCP. Dynamic apps,
  authenticated profiles and arbitrary Internet search providers are not yet supported.
- All automatic HTTP redirects are refused. This avoids a verified redirect
  routing bypass; approved, per-hop redirects are future work.
- Context-wide routing covers frames, resources and initial popup requests;
  WebSockets are closed. Popups/downloads are not exposed as agent capabilities.
- Browser MCP has one serialized page and one fixed session per process. The
  default `default` session matches normal proxy calls. Customized session IDs
  must match the outer proxy context; per-chat session binding is not automatic.
- Detectors are heuristic. There may be false positives and undetected attacks;
  no OCR, image metadata, vision, antivirus or arbitrary binary scanning is claimed.
- Existing frozen v1 evaluation replay keeps its original ASK semantics. New
  Chromium/MCP regression tests verify the stronger B1/B2/B3 release boundary;
  historical evaluation metrics are not evidence of universal protection.
- Ordinary Chrome, built-in IDE browsing/search, and other browser MCPs are not
  automatically instrumented. Future adapters must route these operations or
  ingest their observations before actions are taken.

Implementation references: [Playwright network routing](https://playwright.dev/docs/network),
[route.fetch redirect controls](https://playwright.dev/docs/api/class-route#route-fetch),
[official MCP TypeScript SDK v1](https://ts.sdk.modelcontextprotocol.io/server).
