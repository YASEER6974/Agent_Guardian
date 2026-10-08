# Phase 5: Browser Guardian and cross-surface provenance

Browser Guardian is a controlled Playwright/Chromium research harness. It is not a universal interceptor for arbitrary browser processes. Browser activity is protected when the agent uses this harness, just as MCP activity is protected when the client uses the Guardian proxy.

The agent-facing downstream MCP integration and current live-test evidence are
documented in [Browser MCP setup](browser-mcp-guide.md). It withholds detected
injection (B1) and incomplete inspection (B2) before returning text to the agent,
and refuses unapproved origins / redirects (B3).

## Protected boundary

The harness captures page origin, title, rendered text, DOM-ingested text, frames, links, forms, and network destinations. It compares rendered text with agent-ingested DOM text so hidden content remains attributable to its page.

The following operations are checked before their side effect:

- navigation;
- form submission;
- credential entry;
- purchases;
- downloads;
- non-read network requests, fetches and XHR; in Browser MCP, origins are scoped for all resources and WebSockets are closed;
- browser-influenced system execution.

`ALLOW` proceeds, while `ASK` is held unless the embedding application supplies an approval callback. `BLOCK` never proceeds. The default CLI does not auto-approve held actions.

## Running an observation

Install Chromium once after installing dependencies:

```text
npx playwright install chromium
```

Run the controlled browser:

```text
agent-guardian-browser --url https://example.test --session demo-1
```

Use `--trusted-origin https://example.test` for a controlled origin, `--storage <directory>` to share a non-default Guardian store, and `--headed` to show the browser window.

## Cross-surface enforcement

Browser events are appended to `cross-surface-events.jsonl` in the Guardian storage directory. Records are ordered and SHA-256 hash chained. Invalid JSON, changed records, broken ordering, or broken links fail integrity verification.

The MCP proxy reads the same trace for the same session ID:

- exact browser-text reuse is recorded as `exact-fingerprint` influence;
- transformed or summarized content uses bounded `coarse-session-taint`;
- untrusted browser content influencing an MCP write triggers R8 and requires approval;
- untrusted browser content influencing system execution triggers R7 and is blocked;
- trusted benign content does not trigger those rules merely because it came from a browser.

The browser and MCP calls must use the same session identifier for cross-surface correlation.

## Reproducible twins

The test suite includes two self-hosted pages:

- a benign report with an expected form action;
- a visually similar report containing hidden prompt-injection text.

The Chromium integration test proves that the benign form can proceed and that the poisoned form is held before the HTTP submission reaches the local server.
