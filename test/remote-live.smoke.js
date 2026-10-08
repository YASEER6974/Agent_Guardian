// Optional real Internet MCP smoke test: node test/remote-live.smoke.js
// Uses an isolated database, never changes the workspace's approval settings.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-microsoft-live-'));
fs.writeFileSync(path.join(storage, 'mcp-guardian-db.json'), JSON.stringify({ baselines: {}, logs: [], config: {
  servers: [{ name: 'microsoft-learn', type: 'http', url: 'https://learn.microsoft.com/api/mcp' }],
  autoApproveSafe: true, forbiddenTransitions: [],
  sessionPolicy: { intent: 'Search public Microsoft documentation', allowedCapabilities: ['READ_NETWORK', 'GENERAL'], trustedDestinations: [] },
  resourceLimits: { requestTimeoutMs: 30000 }
} }));
const child = spawn(process.execPath, [path.join(root, 'dist', 'cli.js'), 'proxy'], {
  cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'inherit'],
  env: { ...process.env, MCP_GUARDIAN_STORAGE_PATH: storage, MCP_GUARDIAN_WS_DISABLED: '1', MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: '' }
});
let id = 0;
const pending = new Map();
const reader = readline.createInterface({ input: child.stdout });
reader.on('line', line => { const message = JSON.parse(line); pending.get(message.id)?.(message); });
function request(method, params = {}) {
  const requestId = ++id;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(requestId); reject(new Error(`${method} timed out`)); }, 35000);
    pending.set(requestId, response => { clearTimeout(timer); pending.delete(requestId); resolve(response); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) + '\n');
  });
}
(async () => {
  const initialized = await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'guardian-live-test', version: '1' } });
  assert.ok(initialized.result, JSON.stringify(initialized.error));
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const listed = await request('tools/list');
  assert.ok(listed.result, JSON.stringify(listed.error));
  console.log(`Remote tools inspected by Guardian: ${listed.result.tools.map(tool => tool.name).join(', ')}`);
  const search = listed.result.tools.find(tool => tool.name === 'microsoft-learn__microsoft_docs_search');
  assert.ok(search, 'Remote search tool was absent or rejected by metadata inspection');
  const response = await request('tools/call', { name: search.name, arguments: { query: 'Azure Functions Node.js runtime' } });
  assert.ok(response.result, JSON.stringify(response.error));
  const database = JSON.parse(fs.readFileSync(path.join(storage, 'mcp-guardian-db.json'), 'utf8'));
  const log = database.logs.find(item => item.toolName === 'microsoft_docs_search');
  assert.equal(log.status, 'allow');
  console.log('PASS: AI client → Guardian → Microsoft Learn HTTP MCP → inspected response');
  console.log(`Audit database: ${storage}`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => { child.stdin.end(); reader.close(); });
