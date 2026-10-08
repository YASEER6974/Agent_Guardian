# Agent Guardian

Agent Guardian is a research prototype for protecting AI agents that use Model Context Protocol (MCP) tools and a controlled browser. It places both environments behind one session, evidence model, and policy engine so risky actions can be allowed, held for exact one-time approval, or blocked with an explanation and replayable audit trail.

> **Current status:** Phases 1-7 are complete on the `yaseer` branch. The prototype now includes the security runtime, controlled-browser and MCP enforcement, reproducible evaluation, presentation demo, npm-ready CLI, and packaged VS Code extension.

## Run the presentation demo

```powershell
npm install
npx playwright install chromium
npm run demo:headed
```

The demo is intentionally isolated under [`demo/`](demo/) and uses the real Browser Guardian, policy engine, and hash-chained trace. It runs a malicious invoice twin and a benign authorized twin, proves whether the local side effects occurred, and writes readable PDF, HTML, and Markdown reports plus the raw JSON audit under `demo/output/`. The exact classroom walkthrough is in [`demo/README.md`](demo/README.md).

## Remote HTTP MCP setup

The proxy supports external Streamable HTTP MCP endpoints as well as local stdio servers. In VS Code, use **MCP Guardian: Add External MCP Server** to add a URL or command behind Guardian. **MCP Guardian: Guard Workspace MCP Servers** imports existing workspace connections, saves a backup, and replaces their direct entries with the Guardian proxy.

For remote servers, rejected descriptions are withheld and definitions are checked again before tool calls to detect a rug pull during a session. Static authentication headers and environment-variable references are supported. The local remote example uses Microsoft Learn. See [remote setup and test prompts](docs/remote-mcp-setup.md).

The client must connect through Guardian; direct global entries, private IDE tools and other clients are not automatically intercepted. The 15-day scheduled recheck remains separate future work.

## Research Goal

Agent Guardian investigates this question:

> To what extent does combining user intent, content provenance, tool integrity, and cross-surface data flow improve detection of agent attacks compared with each defense alone?

The contribution is not simply another prompt-injection scanner or MCP proxy. The main research contribution is correlating MCP and browser activity in one ordered trace and gating privileged actions using both user intent and the provenance of the data that influenced them.

## System Overview

```text
Explicit user intent and session policy
        │
        ▼
Onboarding gate for MCP servers
        │
   ┌────┴─────────────────┐
   ▼                      ▼
MCP Guardian         Browser Guardian
- schema integrity   - DOM trust zones
- semantic scans     - content provenance
- output scanning    - action/network gates
- tool/data flow     - visibility checks
   └──────────┬───────────┘
              ▼
      Ordered session trace
              ▼
        Evidence fusion
              ▼
      ALLOW / ASK / BLOCK
              ▼
 Approval UI and hash-chained audit log
```

The browser lane is initially a controlled Playwright/Chromium research harness, not a general-purpose browser extension. The VS Code extension remains the dashboard, configuration, alert, and approval interface. The security proxy will also be packaged as an npm CLI so it can be used by other MCP-compatible clients.

## Decision Model

- **ALLOW:** Execute the action and record the decision.
- **ASK:** Pause execution and show the exact action, reason, affected data, and destination. Approval applies once to that exact action.
- **BLOCK:** Deny malformed, expired, forbidden, previously rejected, or critically unsafe actions.
- Risky actions fail closed if the approval interface is unavailable or the approval expires.
- Deterministic rules make enforcement decisions. An LLM may add semantic evidence but cannot authorize a sensitive action.
- Any attacker-controlled text shown in an approval dialog must be normalized, sanitized, and truncated.

### Initial policy rules

| ID | Condition | Decision |
|---|---|---|
| R1 | Tool definition drifted from its approved baseline | BLOCK until explicit re-baselining |
| R2 | Unknown tool or a tool shadowing another server | ASK; BLOCK in strict mode |
| R3 | Requested capability is outside the session policy | ASK |
| R4 | Sensitive data flows to an untrusted destination | ASK; BLOCK for credentials |
| R5 | Credential access is followed by a remote write | BLOCK |
| R6 | Untrusted content influences a privileged call | ASK |
| R7 | Network content leads to system execution | BLOCK |
| R8 | Untrusted browser content leads to an out-of-intent MCP action | ASK |
| R9 | Hidden, zero-width, or confusable characters are detected | Add evidence and raise applicable R3-R8 severity |

## Shared Security Model

The two enforcement lanes must use the same core types:

- `GuardianSession`: ID, user intent, allowed capabilities, trusted destinations, timestamps, and ordered events.
- `SecurityEvent`: an MCP discovery/call/result or browser observation/action/network request.
- `Evidence`: detector, rule ID, severity, confidence, provenance, explanation, and supporting event IDs.
- `Decision`: ALLOW/ASK/BLOCK, evidence, policy, latency, and final user response.
- `DataLabel`: trusted, untrusted, sensitive, credential, financial, personal, or unknown.
- `DataFlowEdge`: exact value fingerprint or coarse session taint connecting a source event to a later argument, form, request, or destination.
- `CompletenessLedger`: everything inspected, skipped, truncated, timed out, or partially analyzed. An incomplete analysis must never be reported as clean.

User intent is provided out of band through the extension or a session configuration file. Optional per-call context may be carried in MCP `_meta`; ordinary MCP hosts are not expected to call a custom session method.

## Build Plan and Progress

Update this table whenever work begins or a phase is completed. Every completed phase must include tests, a commit, and a push to the `yaseer` branch.

| Phase | Name | Status | Completion evidence |
|---:|---|---|---|
| 1 | Branch, research foundation, and shared core | Complete | Threat model, related work, prototype assessment, shared core, and 6 passing unit tests |
| 2 | MCP runtime stabilization | Complete | Safe spawning, bounded requests, multi-server/concurrent routing, session isolation, approval expiry, audit upserts, and integration tests |
| 3 | MCP Guardian security | Complete | Onboarding, canonical drift, re-baselining, shadowing, Unicode/injection, output, accepted-risk, and data-flow checks; 21 tests pass |
| 4 | Approval channel and reporting | Complete | Exact one-time approval, expiry/replay protection, session policy, safe UI, JSON/JSONL/SARIF exports, CLI exit codes, and 28 tests |
| 5 | Cross-surface stub and Browser Guardian | Complete | Scripted and Chromium twins, pre-action browser gates, tamper-evident provenance, browser-to-MCP R7/R8 enforcement, and 34 tests |
| 6 | Research evaluation | Complete | Frozen 25-case corpus/policy, 14 configurations, held-out results, live Chromium repeats, Wilson intervals, exports, and 39 tests |
| 7 | Final demo, packaging, and documentation | Complete | Malicious/benign live demo, 43 passing tests, verified npm dry-run, packaged VSIX, cross-surface dashboard timeline, and client guides |

### Phase 1 - Branch, research foundation, and shared core

- Verify the prototype and record its current defects before changing behavior.
- Write the threat model: adaptive attacker, guard-targeted text, malicious MCP metadata/results, and untrusted browser content.
- Document related work honestly, including overlapping MCP runtime and policy projects.
- Implement the shared types, uniform evidence format, detector registry, completeness ledger, hash-chained JSONL audit trail, and deterministic rule engine.
- Add unit tests that run without an MCP server or browser.

**Done when:** the agreed claim and threat model are documented, and all core-library tests pass.

### Phase 2 - MCP runtime stabilization

- Remove shell-based downstream server launching.
- Correct multi-server tool discovery and concurrent JSON-RPC request routing.
- Preserve numeric and string client request IDs safely.
- Isolate session traces and add request, downstream-server, and approval timeouts.
- Update audit decisions instead of inserting duplicate records.
- Add clean shutdown and downstream failure handling.
- Bound untrusted payload size, nesting depth, output size, and processing time.
- Replace manual demonstration scripts with automated Windows-compatible integration tests.

**Done when:** two or more mock servers route reliably under concurrent calls, failures cannot hang the proxy, and audit rows remain unique.

### Phase 3 - MCP Guardian security

- Add an onboarding gate that statically scans a server before trusting its first baseline.
- Canonicalize and fingerprint descriptions, parameters, nested schemas, defaults, enums, annotations, resources, and prompts.
- Keep trusted and observed definitions separate; show exact per-field drift and require explicit re-baselining.
- Detect unknown tools and cross-server tool shadowing.
- Normalize and scan Unicode confusables, zero-width characters, and whitespace obfuscation in every relevant string.
- Recursively scan metadata, arguments, resources, and tool results.
- Track exact value flow plus coarse session taint when data is summarized, transformed, or re-encoded.
- Run optional semantic analysis in a sandboxed, tool-free process with a scrubbed environment, timeout, and structured output.
- Add an accepted-risk file whose entries include a reason and version-bound fingerprint, separate from the trust baseline.

**Done when:** drifted tools cannot execute silently, partial scans are reported honestly, and benign and malicious capability chains receive different decisions.

### Phase 4 - Approval channel and reporting

- Implement out-of-band session start through the extension/configuration and optional MCP `_meta` context.
- Implement `approve_once` and `deny`, with expiry shorter than the MCP client's request timeout.
- Sanitize and truncate explanations while preserving safe evidence references.
- Display intent, proposed action, affected data, destination, and policy rule.
- Export JSON, JSONL audit traces, and SARIF; provide meaningful CLI exit codes and display-only risk bands.
- If time permits, scan MCP client configuration for broad allow lists and risky hooks.

**Done when:** ASK pauses a real call and only the exact approved action resumes; rejected, expired, or unavailable approvals fail closed.

Phase 4 usage, `_meta` session context, reporting commands, and exit codes are documented in [`docs/phase-4-usage.md`](docs/phase-4-usage.md).

### Phase 5 - Cross-surface stub and Browser Guardian

- First feed scripted browser events into the shared trace so cross-surface rules can be tested before browser automation is complete.
- Implement R6-R8 against malicious and benign twin traces.
- Build a Playwright/Chromium harness using self-hosted test pages.
- Capture DOM structure, frames, visible text, forms, links, origins, and network destinations.
- Create trust zones and retain provenance from observed content into later actions.
- Compare rendered content with content ingested by the agent and localize suspicious segments contextually.
- Gate navigation, downloads, form submissions, credential entry, purchases, and cross-origin requests before their side effects occur.
- Keep untrusted-content masking as an optional ablation, not the default defense.

**Done when:** sensitive browser actions are held before execution and their provenance survives into later MCP decisions.

The controlled-browser commands, trust boundary, supported gates, and cross-surface trace format are documented in [`docs/phase-5-browser-guardian.md`](docs/phase-5-browser-guardian.md).

### Phase 6 - Research evaluation

- Build a labelled JSONL corpus of benign and malicious mock-MCP and self-hosted-browser scenarios.
- Cover metadata poisoning, rug pull, nested schema poisoning, shadowing, malicious arguments/results, browser injection, delayed attacks, guard-targeted instructions, confused-deputy chains, and browser/MCP exfiltration.
- Include held-out cases derived from external benchmarks where licensing and availability permit.
- Freeze the rule table before running held-out tests.
- Support deterministic trace replay plus a smaller repeated live-agent subset.
- Run baseline, single-layer, full-system, leave-one-layer-out, MCP-only, and browser-only configurations.
- Report attack success, precision, recall, F1, false positives/negatives, benign completion, permission frequency, overrides, latency, memory, and confidence intervals.
- Report partial attacker influence separately from completed attacker goals.

**Done when:** one command reproduces the corpus run, ablation table, metrics, and confidence intervals.

Run `npm run evaluate` to reproduce the deterministic corpus, ablation tables, held-out metrics, CSV/JSON results, and repeated live Chromium subset. The methodology and limitations are documented in [`docs/phase-6-evaluation.md`](docs/phase-6-evaluation.md).

### Phase 7 - Final demo, packaging, and documentation

- Malicious demo: an invoice request encounters untrusted content, attempts credential access, and tries an external email; Guardian pauses before the side effect.
- Benign twin: the user explicitly asks to read a report and send it to an approved professor; Guardian allows it.
- Update the VS Code dashboard to show intent, ordered trace, evidence, pending permission, and outcome.
- Package the cross-client proxy as an npm CLI while retaining the VS Code extension as the optional approval/dashboard interface.
- Document installation for VS Code, Cursor, Claude Desktop, Windsurf, and generic MCP-compatible clients where applicable.
- Align the project website with the implemented scope and measured results.

**Done when:** both demonstrations run end to end, the npm package can be installed locally, the extension works with it, and a new contributor can reproduce the evaluation from the documentation.

Phase 7 is implemented and verified. Use these entry points:

- [`demo/README.md`](demo/README.md): isolated live demo and five-minute presentation script.
- [`docs/phase-7-installation.md`](docs/phase-7-installation.md): npm, VS Code, Cursor, Claude Desktop, Windsurf, and generic stdio MCP setup.
- [`docs/website-copy.md`](docs/website-copy.md): accurate website wording aligned with the implemented scope and Phase 6 results.
- `npm run demo`: headless end-to-end demo.
- `npm run demo:headed`: visible classroom demo.
- `npm run pack:check`: verify the npm package contents without publishing.

The local extension artifact can be rebuilt with `npx --yes @vscode/vsce package`. The npm package is prepared for local tarball installation but has not been published; publishing requires the repository owner's approval and an agreed registry name.

## Evaluation Matrix

| Configuration | Integrity | Semantic | Behavior | Intent | Provenance |
|---|---:|---:|---:|---:|---:|
| No Guardian | Off | Off | Off | Off | Off |
| Each layer alone | One at a time | One at a time | One at a time | One at a time | One at a time |
| Full Guardian | On | On | On | On | On |
| Full minus Integrity | Off | On | On | On | On |
| Full minus Semantic | On | Off | On | On | On |
| Full minus Behavior | On | On | Off | On | On |
| Full minus Intent | On | On | On | Off | On |
| Full minus Provenance | On | On | On | On | Off |
| MCP-only / Browser-only | Per lane | Per lane | Per lane | On | Per lane |

Required benign controls include intentional file-to-email workflows, invoice retrieval, approved form submission, harmless imperative webpage text, and explicitly authorized versions of otherwise dangerous-looking sequences.

## Distribution Strategy

Agent Guardian will support both forms from one GitHub repository:

- **npm package:** the cross-platform MCP proxy and CLI for MCP-compatible clients.
- **VS Code extension:** configuration, monitoring, evidence display, and permission requests.
- **GitHub repository:** source code, browser harness, benchmark corpus, research results, issues, and releases.

The security core must not depend on VS Code. If the extension is absent, safe actions may proceed according to policy, while actions requiring approval fail closed.

## Repository and Team Workflow

- Development for this plan happens on the `yaseer` branch.
- Do not push implementation directly to `main`.
- Pull/fetch before starting work and confirm the working tree is clean.
- Use one focused commit per meaningful unit of work; at minimum, commit and push at the end of every phase.
- Update the progress table and record test commands/results in the phase-completion commit.
- Never commit API keys, credentials, personal traces, generated dependency folders, or unsanitized sensitive audit data.
- Team members should continue from the first phase not marked complete, after rerunning the previous phase's tests.
- Merge to `main` only after team review and final integration testing.

## Scope Priorities

If time becomes limited, remove features in this order:

1. Untrusted-content masking ablation.
2. Dashboard polish.
3. Semantic-model integration.
4. SARIF export.
5. Client-configuration analyzer.

Do not remove the shared core, stable MCP runtime, enforceable MCP protections, cross-surface trace, deterministic evaluation, or benign controls; these carry the research contribution.

## Existing Prototype Layout

```text
src/
  proxy.ts               MCP stdio proxy and runtime routing
  detector.ts            Current integrity, heuristic, and category checks
  db.ts                  Local baseline/configuration/audit storage
  extension.ts           VS Code extension and approval channel
  types.ts               Shared prototype types
  webview/sidebar.html   VS Code dashboard
scratch/
  mock_server.js         Mock MCP server
  test_client.js         Manual test client
  test_online_approval.js
  setup_test_db.js
```

This layout will evolve during Phase 1 so the shared core, detectors, policy engine, transports, browser harness, and evaluation code have explicit boundaries.

## License and Attribution

Ideas may be adapted from relevant research and open-source security projects. When source code is copied or modified, preserve its license headers and add required notices. In particular, NVIDIA SkillSpector is Apache-2.0 licensed; calling it as a tool or reimplementing general ideas does not remove attribution obligations for copied code.
