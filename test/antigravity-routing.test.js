const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { parse } = require('jsonc-parser');
const cli = path.resolve(__dirname, '../dist/cli.js');

function fixture(servers) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-routing-'));
  const config = path.join(root, 'mcp_config.json');
  const original = '// keep this comment\n' + JSON.stringify({ mcpServers: servers, other: 'keep' });
  fs.writeFileSync(config, original);
  return { root, config, original };
}
function route(f) {
  return spawnSync(process.execPath, [cli, 'config', 'guard-antigravity', '--config', f.config, '--workspace', f.root, '--port', '1340'], { encoding: 'utf8' });
}
test('Antigravity routing imports HTTP and stdio behind one proxy and preserves a backup', () => {
  const f = fixture({ docs: { serverUrl: 'https://example.test/mcp', headers: { Authorization: 'Bearer ${env:DEMO_TOKEN}' } },
    local: { command: 'node', args: ['${workspaceFolder}/server.js'] } });
  const result = route(f);
  assert.equal(result.status, 0, result.stderr);
  const config = parse(fs.readFileSync(f.config, 'utf8'));
  assert.deepEqual(Object.keys(config.mcpServers), ['agent-guardian']);
  assert.equal(config.other, 'keep');
  assert.match(fs.readFileSync(f.config, 'utf8'), /keep this comment/);
  assert.equal(config.mcpServers['agent-guardian'].env.MCP_GUARDIAN_WS_PORT, '1340');
  const settings = parse(fs.readFileSync(path.join(f.root, '.vscode/settings.json'), 'utf8'));
  assert.equal(settings['mcp-guardian.wsPort'], 1340);
  assert.equal(settings['mcp-guardian.servers'][0].headers.Authorization, 'Bearer ${env:DEMO_TOKEN}');
  assert.equal(settings['mcp-guardian.servers'][1].args[0], f.root + '/server.js');
  const backup = fs.readdirSync(f.root).find(name => name.includes('.guardian-backup-'));
  assert.equal(fs.readFileSync(path.join(f.root, backup), 'utf8'), f.original);
  assert.equal(route(f).status, 0, 'Routing twice must not import Guardian into itself');
});
test('Antigravity routing refuses OAuth and disabled-tool constraints without modifying files', () => {
  for (const extra of [{ oauth: { clientId: 'demo' } }, { disabledTools: ['delete_project'] }, { disabled: true }, { tools: {} }]) {
    const f = fixture({ docs: { serverUrl: 'https://example.test/mcp', ...extra } });
    const result = route(f);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unsupported/);
    assert.equal(fs.readFileSync(f.config, 'utf8'), f.original);
    assert.equal(fs.existsSync(path.join(f.root, '.vscode/settings.json')), false);
  }
});
