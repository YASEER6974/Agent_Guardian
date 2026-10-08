const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const test = require('node:test');
const { chromium } = require('playwright');

test('definition review shows exact changes, requires review and treats metadata as text', { timeout: 20000 }, async t => {
  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 420, height: 900 } });
  await page.addInitScript(() => {
    globalThis.sent = [];
    globalThis.acquireVsCodeApi = () => ({ postMessage(message) { sent.push(message); }, getState() {}, setState() {} });
  });
  await page.goto(pathToFileURL(path.join(__dirname, '..', 'src/webview/sidebar.html')).href);
  const baseline = { name: 'search', description: 'Old description', hash: 'a'.repeat(64), category: 'READ_NETWORK',
    approved: false, status: 'drifted', observedHash: 'b'.repeat(64), inspection: { complete: true }, evidence: [],
    observedDefinition: { description: '<img src=x onerror="window.injected=true">New description' },
    differences: [{ path: '$.description', kind: 'changed', before: 'Old description', after: 'New description' }] };
  const state = { type: 'sync', proxyConnected: true, config: { servers: [], sessionPolicy: {} },
    baselines: { remote: { "search' onclick='bad": baseline } }, logs: [], pendingApprovals: [], crossSurfaceRecords: [], traceIntegrity: true };
  await page.evaluate(message => window.dispatchEvent(new MessageEvent('message', { data: message })), state);
  await page.evaluate(() => switchTab('rules', document.querySelectorAll('.tab-btn')[1]));
  await page.locator('.definition-review > summary').click();
  const rules = await page.locator('#rules-container').textContent();
  assert.match(rules, /Old description/);
  assert.match(rules, /New description/);
  assert.match(rules, /\$\.description/);
  assert.equal(await page.locator('#rules-container img').count(), 0);
  assert.equal(await page.locator('.accept-definition').isDisabled(), true);
  await page.locator('.review-definition').check();
  await page.locator('.accept-definition').click();
  const approved = await page.evaluate(() => sent.find(item => item.type === 'approve_drift'));
  assert.equal(approved.toolName, "search' onclick='bad");
  assert.equal(approved.newHash, 'b'.repeat(64));
  baseline.status = 'rejected';
  baseline.evidence = [{ ruleId: 'R2', message: 'Injection detected' }];
  await page.evaluate(message => window.dispatchEvent(new MessageEvent('message', { data: message })), state);
  assert.equal(await page.locator('.accept-definition').count(), 0);
  assert.match(await page.locator('#rules-container').textContent(), /Injection detected/);
  baseline.status = 'pending';
  baseline.evidence = [];
  baseline.inspection.complete = false;
  await page.evaluate(message => window.dispatchEvent(new MessageEvent('message', { data: message })), state);
  assert.equal(await page.locator('.accept-definition').count(), 0);
  assert.doesNotMatch(await page.locator('#rules-container').textContent(), /Metadata changed/);
});

test('dashboard renders fresh remote metadata, intent, counters and completed approval state', { timeout: 20000 }, async t => {
  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    globalThis.acquireVsCodeApi = () => ({ postMessage() {}, getState() {}, setState() {} });
  });
  await page.goto(pathToFileURL(path.join(__dirname, '..', 'src', 'webview', 'sidebar.html')).href);
  const timestamp = new Date().toISOString();
  const state = {
    type: 'sync', proxyConnected: true, connectionPort: 1338, traceIntegrity: true,
    config: { servers: [{ name: 'microsoft-learn', type: 'http', url: 'https://learn.microsoft.com/api/mcp' }],
      sessionPolicy: { intent: 'Read Microsoft documentation' } },
    baselines: { 'microsoft-learn': { microsoft_docs_search: {
      name: 'microsoft_docs_search', description: 'Search public documentation', hash: 'a'.repeat(64),
      category: 'READ_NETWORK', approved: true
    } } },
    logs: [{ id: 'call-1', timestamp, serverName: 'microsoft-learn', toolName: 'microsoft_docs_search',
      category: 'READ_NETWORK', arguments: {}, status: 'pending', intent: 'Read Microsoft documentation' }],
    pendingApprovals: [{ id: 'call-1', actionFingerprint: 'b'.repeat(64), serverName: 'microsoft-learn',
      toolName: 'microsoft_docs_search', intent: 'Read Microsoft documentation', capability: 'READ_NETWORK',
      reason: 'Manual confirmation required', arguments: {}, evidence: [], expiresAt: new Date(Date.now() + 60000).toISOString() }],
    crossSurfaceRecords: []
  };
  await page.evaluate(message => window.dispatchEvent(new MessageEvent('message', { data: message })), state);
  assert.equal(await page.locator('#connection-text').textContent(), 'SHIELD ACTIVE');
  assert.equal(await page.locator('#session-intent').textContent(), 'Read Microsoft documentation');
  assert.match(await page.locator('#rules-container').textContent(), /microsoft-learn__microsoft_docs_search/);
  assert.match(await page.locator('#servers-container').textContent(), /https:\/\/learn.microsoft.com\/api\/mcp/);
  assert.equal(await page.locator('#pending-container .alert-card').count(), 1);
  state.logs[0].status = 'allow';
  state.pendingApprovals = [];
  await page.evaluate(message => window.dispatchEvent(new MessageEvent('message', { data: message })), state);
  assert.equal(await page.locator('#stat-allowed').textContent(), '1');
  assert.equal(await page.locator('#pending-container .alert-card').count(), 0);
  assert.match(await page.locator('#logs-container').textContent(), /microsoft-learn__microsoft_docs_search/);
  assert.equal(errors.length, 0, errors.join('\n'));
});
