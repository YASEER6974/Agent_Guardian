// Optional authenticated, read-only Vercel discovery through Guardian.
// OAuth credentials are managed only by mcp-remote; this script never reads them.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-vercel-live-'));
fs.writeFileSync(path.join(storage, 'mcp-guardian-db.json'), JSON.stringify({ baselines: {}, logs: [], config: {
  servers: [{ name: 'vercel', command: 'cmd', args: ['/c', 'npx', '-y', 'mcp-remote@0.14.3', 'https://mcp.vercel.com'] }],
  // Explicit --read mode permits only the two hardcoded list operations below.
  // This isolated policy does not change the workspace's manual approvals.
  autoApproveSafe: process.argv.includes('--read'), forbiddenTransitions: [],
  sessionPolicy: { intent: 'Discover external Vercel tools only; no deployment', allowedCapabilities: ['READ_LOCAL', 'READ_NETWORK'], trustedDestinations: [] },
  resourceLimits: { requestTimeoutMs: 30000 }
} }));
const child = spawn(process.execPath, [path.join(root, 'dist/cli.js'), 'proxy'], {
  cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, MCP_GUARDIAN_STORAGE_PATH: storage, MCP_GUARDIAN_WS_DISABLED: '1', MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: '' }
});
let sequence = 0;
const pending = new Map();
child.stderr.on('data', data => {
  // Never echo OAuth URLs/codes/credential-bearing diagnostics from the bridge.
  const safe = data.toString().split('\n').filter(line => line.startsWith('[MCP-Guardian-Proxy]'));
  for (const line of safe) console.error(line);
});
const reader = readline.createInterface({ input: child.stdout });
reader.on('line', line => {
  const message = JSON.parse(line);
  pending.get(message.id)?.(message);
});
function request(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 35000);
    pending.set(id, message => { clearTimeout(timer); pending.delete(id); resolve(message); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
(async () => {
  const initialized = await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'agent-guardian-vercel-test', version: '1' } });
  assert.ok(initialized.result, JSON.stringify(initialized.error));
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const listed = await request('tools/list');
  assert.ok(listed.result, JSON.stringify(listed.error));
  const database = JSON.parse(fs.readFileSync(path.join(storage, 'mcp-guardian-db.json'), 'utf8'));
  const baselines = database.baselines.vercel || {};
  fs.writeFileSync(path.join(storage, 'discovered-tools.json'), JSON.stringify(listed.result.tools));
  console.log(JSON.stringify({ exposedToolCount: listed.result.tools.length,
    rejectedToolCount: Object.values(baselines).filter(item => item.status === 'rejected').length,
    relevantTools: listed.result.tools.filter(tool => /__(?:create_deployment|create_project|get_deployment|list_teams|list_projects)$/.test(tool.name)).map(tool => ({ name: tool.name, required: tool.inputSchema.required, inputs: Object.keys(tool.inputSchema.properties || {}) })),
    auditDirectory: storage }, null, 2));
  assert.ok(Object.keys(baselines).length, 'Vercel supplied no discoverable definitions');
  if (process.argv.includes('--read')) {
    for (const name of ['vercel__list_teams', 'vercel__list_projects']) {
      assert.ok(listed.result.tools.some(tool => tool.name === name));
      const response = await request('tools/call', { name, arguments: { limit: name === 'vercel__list_projects' ? '10' : 10 } });
      assert.ok(response.result && !response.result.isError, JSON.stringify(response.error || response.result));
      console.log(`READ RESULT ${name}: ${JSON.stringify(response.result).slice(0, 7000)}`);
    }
  }
  console.log('PASS: client → Guardian → authenticated bridge → real Vercel MCP; no write operation or deployment executed.');
})().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => { child.stdin.end(); reader.close(); });
