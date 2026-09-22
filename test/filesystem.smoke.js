// Optional live MCP smoke test. Run with: node test/filesystem.smoke.js
// It uses a temporary Guardian database and only reads files in test-files.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');

const root = path.join(__dirname, '..');
const allowed = path.join(root, '.mcp-guardian', 'test-files');
const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guardian-filesystem-'));
fs.writeFileSync(path.join(storage, 'mcp-guardian-db.json'), JSON.stringify({
  baselines: {}, logs: [], config: {
    servers: [{ name: 'filesystem', command: 'cmd', args: [
      '/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem@2026.8.31', allowed
    ] }],
    forbiddenTransitions: [], geminiApiKey: '', autoApproveSafe: true,
    firstSeenPolicy: 'approve-safe',
    sessionPolicy: { intent: 'Read demonstration files', allowedCapabilities: ['READ_LOCAL'], trustedDestinations: [] },
    resourceLimits: { requestTimeoutMs: 60000 }
  }
}));

const child = spawn(process.execPath, [path.join(root, 'dist', 'proxy.js')], {
  cwd: root, stdio: ['pipe', 'pipe', 'inherit'], windowsHide: true,
  env: { ...process.env, MCP_GUARDIAN_STORAGE_PATH: storage, MCP_GUARDIAN_WS_DISABLED: '1' }
});
let id = 0;
const pending = new Map();
readline.createInterface({ input: child.stdout }).on('line', line => {
  const message = JSON.parse(line);
  const handle = pending.get(message.id);
  if (handle) { pending.delete(message.id); handle(message); }
});
function request(method, params = {}) {
  const requestId = ++id;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(requestId); reject(new Error(`${method} timed out`)); }, 70000);
    pending.set(requestId, response => { clearTimeout(timer); resolve(response); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) + '\n');
  });
}

(async () => {
  const initialized = await request('initialize', {
    protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'guardian-smoke', version: '1.0.0' }
  });
  assert.ok(initialized.result, JSON.stringify(initialized.error));
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const listed = await request('tools/list');
  assert.ok(listed.result, JSON.stringify(listed.error));
  const tools = listed.result.tools || [];
  console.log(`Guardian discovered ${tools.length} filesystem tools`);
  assert.ok(tools.length > 0);
  assert.ok(tools.every(tool => tool.name.startsWith('filesystem__')));
  const readTool = tools.find(tool => tool.name === 'filesystem__read_text_file');
  assert.ok(readTool, `Filesystem read_text_file tool missing: ${tools.map(tool => tool.name).join(', ')}`);
  const clean = await request('tools/call', {
    name: readTool.name, arguments: { path: path.join(allowed, 'clean.txt') }
  });
  assert.ok(clean.result, `Clean file was not readable: ${JSON.stringify(clean.error)}`);
  console.log('Guardian allowed clean.txt');
  const poisoned = await request('tools/call', {
    name: readTool.name, arguments: { path: path.join(allowed, 'poisoned.txt') }
  });
  assert.ok(poisoned.error, 'Guardian returned the poisoned file to the client');
  console.log(`Guardian blocked poisoned.txt: ${poisoned.error.message}`);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
}).finally(() => child.stdin.end());
