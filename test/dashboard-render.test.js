const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const test = require('node:test');
const { chromium } = require('playwright');

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
