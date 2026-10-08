const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

// Scripted MCP client: the browser is never called directly in this verification
// helper. Its tools are discovered and called through the production proxy.
async function startBrowserClient({ origins, trustedOrigins = [], allowForms = false, storagePath, headed = false }) {
  const root = path.resolve(__dirname, '..');
  storagePath ||= fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-browser-mcp-'));
  const args = [path.join(root, 'dist', 'browser-mcp.js'), '--storage', storagePath,
    ...origins.flatMap(origin => ['--allowed-origin', origin]),
    ...trustedOrigins.flatMap(origin => ['--trusted-origin', origin]),
    ...(allowForms ? ['--allow-forms'] : []), ...(headed ? ['--headed'] : [])];
  fs.mkdirSync(storagePath, { recursive: true });
  fs.writeFileSync(path.join(storagePath, 'mcp-guardian-db.json'), JSON.stringify({ baselines: {}, logs: [], config: {
    servers: [{ name: 'browser', command: process.execPath, args }],
    forbiddenTransitions: [], autoApproveSafe: true, geminiApiKey: '',
    sessionPolicy: { intent: 'Verify guarded browser with synthetic data only',
      allowedCapabilities: ['READ_NETWORK', ...(allowForms ? ['WRITE_COMMUNICATION'] : [])], trustedDestinations: trustedOrigins }
  } }));
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(root, 'dist', 'cli.js'), 'proxy'], cwd: root, stderr: 'pipe',
    env: { ...process.env, MCP_GUARDIAN_STORAGE_PATH: storagePath, MCP_GUARDIAN_WS_DISABLED: '1', MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: '' }
  });
  let stderr = '';
  transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
  const client = new Client({ name: 'guardian-browser-verification', version: '1.0.0' });
  try { await client.connect(transport); await client.listTools(); } catch (error) { await client.close(); throw error; }
  return { client, storagePath, stderr: () => stderr,
    call: async (name, args) => {
      const result = await client.callTool({ name: `browser__${name}`, arguments: args });
      return { result, report: JSON.parse(result.content.find(item => item.type === 'text').text) };
    }, close: () => client.close() };
}

module.exports = { startBrowserClient };
