const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const vm = require('node:vm');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const test = require('node:test');
const WebSocket = require('ws');

const root = path.resolve(__dirname, '..');

async function waitFor(predicate, message) {
  const deadline = Date.now() + 6000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(message);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function extensionHost(port, withLaunchEnvironment = true, workspaceConfigured = false, manualApprovals = false) {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-dashboard-'));
  fs.mkdirSync(path.join(storage, '.vscode'));
  const settingsPath = path.join(storage, '.vscode', 'settings.json');
  fs.writeFileSync(settingsPath, JSON.stringify({
    'mcp-guardian.storagePath': storage,
    'mcp-guardian.wsPort': port,
    'mcp-guardian.servers': [{
      name: 'dashboard-test', command: process.execPath,
      args: [path.join(root, 'test', 'fixtures', 'mock-mcp-server.js')]
    }],
    'mcp-guardian.autoApproveSafe': false,
    'mcp-guardian.sessionIntent': 'Verify the dashboard connection',
    'mcp-guardian.allowedCapabilities': [],
    'mcp-guardian.forbiddenTransitions': []
  }));
  const env = {
    ...process.env,
    MCP_GUARDIAN_STORAGE_PATH: storage,
    MCP_GUARDIAN_WS_PORT: String(port),
    MCP_GUARDIAN_WS_DISABLED: '0',
    MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: settingsPath
  };
  if (!withLaunchEnvironment) {
    delete env.MCP_GUARDIAN_STORAGE_PATH;
    delete env.MCP_GUARDIAN_WS_PORT;
    delete env.MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH;
  }
  const snapshots = [], errors = [], approvals = [], information = [], inputQueue = [];
  const commands = new Map();
  let provider, receive, mcpProvider, mcpProviderId;
  if (workspaceConfigured) {
    fs.writeFileSync(path.join(storage, '.vscode', 'mcp.json'), JSON.stringify({ servers: { 'agent-guardian': { command: 'node' } } }));
  }
  // Reproduce an empty development window with setting defaults/stale storage.
  const defaults = { wsPort: 1337, storagePath: path.join(storage, 'stale'), servers: [], sessionIntent: '' };
  const disposable = { dispose() {} };
  const vscode = {
    ExtensionMode: { Development: 2 },
    McpStdioServerDefinition: class {
      constructor(label, command, args, env) { Object.assign(this, { label, command, args, env }); }
    },
    lm: {
      registerMcpServerDefinitionProvider: (id, value) => {
        mcpProviderId = id; mcpProvider = value; return disposable;
      }
    },
    workspace: {
      workspaceFolders: workspaceConfigured ? [{ uri: { fsPath: storage } }] : [],
      getConfiguration: () => ({ get: key => defaults[key] }),
      onDidChangeConfiguration: () => disposable
    },
    window: {
      registerWebviewViewProvider: (_, value) => { provider = value; return disposable; },
      showErrorMessage: async message => { errors.push(message); },
      showInformationMessage: async message => { information.push(message); },
      showQuickPick: async items => items[0],
      showInputBox: async () => inputQueue.shift(),
      showOpenDialog: async () => [{ fsPath: inputQueue.shift() }],
      showWarningMessage: message => { approvals.push(message); return manualApprovals ? new Promise(() => {}) : Promise.resolve('Approve Once'); }
    },
    commands: { registerCommand: (id, handler) => { commands.set(id, handler); return disposable; } }
  };
  const module = { exports: {} };
  const extensionPath = path.join(root, 'dist', 'extension.js');
  vm.runInNewContext(fs.readFileSync(extensionPath, 'utf8'), {
    module, exports: module.exports,
    require: name => name === 'vscode' ? vscode : require(name),
    __dirname: path.dirname(extensionPath), __filename: extensionPath,
    process: { ...process, env }, Buffer, URL, structuredClone,
    setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate,
    console: { log() {}, error() {}, warn() {} }
  }, { filename: extensionPath });
  module.exports.activate({ subscriptions: [], extensionMode: 2, extensionUri: { fsPath: storage } });
  provider.resolveWebviewView({
    webview: {
      postMessage: value => { snapshots.push(JSON.parse(JSON.stringify(value))); return Promise.resolve(true); },
      onDidReceiveMessage: callback => { receive = callback; return disposable; }
    },
    onDidChangeVisibility: () => disposable
  }, {}, {});
  receive({ type: 'request_sync' });
  return {
    storage, env, snapshots, errors, approvals,
    information, inputQueue, runCommand: id => commands.get(id)(),
    mcpProviderId, mcpDefinitions: () => mcpProvider.provideMcpServerDefinitions(),
    sendWebview: message => receive(message),
    state: () => snapshots.at(-1),
    deactivate: () => module.exports.deactivate()
  };
}

function startProxy(env, definition) {
  const child = spawn(definition?.command || process.execPath, definition?.args || [path.join(root, 'dist', 'cli.js'), 'proxy'], {
    cwd: definition?.cwd.fsPath || root, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe']
  });
  let stderr = '', sequence = 0;
  child.stderr.on('data', value => { stderr += value; });
  const reader = readline.createInterface({ input: child.stdout });
  const pending = new Map();
  reader.on('line', line => {
    const message = JSON.parse(line);
    pending.get(message.id)?.(message);
  });
  const request = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out: ${stderr}`)); }, 6000);
    pending.set(id, value => { clearTimeout(timer); pending.delete(id); resolve(value); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  const stop = async () => {
    if (child.exitCode !== null) return;
    const exited = once(child, 'exit');
    const timer = setTimeout(() => child.kill(), 2000);
    child.stdin.end();
    await exited;
    clearTimeout(timer);
    reader.close();
  };
  return { request, stop, stderr: () => stderr };
}

test('empty development host shares config with the real proxy and completes approval after connecting', async t => {
  const port = await freePort();
  const host = extensionHost(port);
  t.after(() => host.deactivate());
  const proxy = startProxy(host.env);
  t.after(() => proxy.stop());
  await waitFor(() => host.state().proxyConnected, 'Dashboard never became active');
  assert.equal(host.state().connectionPort, port);
  assert.equal(host.state().config.sessionPolicy.intent, 'Verify the dashboard connection');
  assert.equal(fs.existsSync(path.join(host.storage, 'stale')), false, 'Stale store must not be opened');
  const initialized = await proxy.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  assert.ok(initialized.result, JSON.stringify(initialized.error));
  const listed = await proxy.request('tools/list');
  assert.ok(listed.result.tools.some(tool => tool.name === 'dashboard-test__echo'));
  await waitFor(() => host.state().baselines['dashboard-test']?.echo, 'Discovered tool definitions never reached the dashboard');
  const called = await proxy.request('tools/call', { name: 'dashboard-test__echo', arguments: { value: 'hello' } });
  assert.ok(called.result, JSON.stringify(called.error));
  assert.equal(host.approvals.length, 1);
  await waitFor(() => host.state().logs.some(log => log.status === 'allow'), 'Approval result never reached dashboard');
  assert.ok(JSON.parse(fs.readFileSync(path.join(host.storage, 'mcp-guardian-db.json'), 'utf8')).baselines['dashboard-test'].echo,
    'Dashboard log handling erased the proxy baseline');
  assert.match(proxy.stderr(), new RegExp(`Connected to VS Code extension on port ${port}`));
  assert.equal(host.errors.length, 0);
  await proxy.stop();
  await waitFor(() => !host.state().proxyConnected, 'Dashboard stayed active after disconnect');
  const restarted = startProxy(host.env);
  t.after(() => restarted.stop());
  await waitFor(() => host.state().proxyConnected, 'Dashboard never reflected the restarted proxy');
});

test('dashboard updates connect and disconnect without depending on a later sync message', async t => {
  const port = await freePort();
  const host = extensionHost(port);
  t.after(() => host.deactivate());
  const socket = new WebSocket(`ws://127.0.0.1:${port}`);
  t.after(() => socket.terminate());
  await once(socket, 'open');
  await waitFor(() => host.state().proxyConnected, 'Connection event did not update dashboard');
  socket.close();
  await once(socket, 'close');
  await waitFor(() => !host.state().proxyConnected, 'Close event did not update dashboard');
});

test('development folder settings select the matching port even when launch environment is absent', async t => {
  const port = await freePort();
  const host = extensionHost(port, false);
  t.after(() => host.deactivate());
  const socket = new WebSocket(`ws://127.0.0.1:${port}`);
  t.after(() => socket.terminate());
  await once(socket, 'open');
  await waitFor(() => host.state().proxyConnected, 'Development settings were not loaded');
  assert.equal(host.state().connectionPort, port);
  assert.equal(host.state().config.sessionPolicy.intent, 'Verify the dashboard connection');
  assert.equal(fs.existsSync(path.join(host.storage, 'stale')), false);
});

test('empty development host contributes a runnable MCP server with its own connection settings', async t => {
  const port = await freePort();
  const host = extensionHost(port, false);
  t.after(() => host.deactivate());
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.ok(manifest.contributes.mcpServerDefinitionProviders.some(item => item.id === host.mcpProviderId));
  const definitions = host.mcpDefinitions();
  assert.equal(definitions.length, 1);
  const definition = definitions[0];
  assert.equal(definition.label, 'agent-guardian');
  assert.equal(definition.command, 'node');
  assert.equal(definition.args[1], 'proxy');
  assert.equal(definition.cwd.fsPath, host.storage);
  assert.equal(definition.env.MCP_GUARDIAN_WS_PORT, String(port));
  assert.equal(definition.env.MCP_GUARDIAN_STORAGE_PATH, host.storage);
  // Populate the isolated extension directory with the real bundles, then
  // execute the provider's command, arguments, cwd and environment unchanged.
  fs.mkdirSync(path.join(host.storage, 'dist'));
  for (const bundle of ['cli.js', 'proxy.js']) {
    fs.copyFileSync(path.join(root, 'dist', bundle), path.join(host.storage, 'dist', bundle));
  }
  const proxy = startProxy({ ...process.env, ...definition.env }, definition);
  t.after(() => proxy.stop());
  await waitFor(() => host.state().proxyConnected, 'Contributed MCP server did not connect to dashboard');
  const initialized = await proxy.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  assert.ok(initialized.result, JSON.stringify(initialized.error));
  const listed = await proxy.request('tools/list');
  assert.ok(listed.result.tools.some(tool => tool.name === 'dashboard-test__echo'));
});

test('workspace MCP configuration suppresses the duplicate extension-provided proxy', async t => {
  const host = extensionHost(await freePort(), true, true);
  t.after(() => host.deactivate());
  assert.equal(host.mcpDefinitions().length, 0);
});

test('a busy dashboard port reports the cause without crashing the extension', async t => {
  const occupied = new WebSocket.WebSocketServer({ port: 0, host: '127.0.0.1' });
  await once(occupied, 'listening');
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  const port = occupied.address().port;
  const host = extensionHost(port);
  t.after(() => host.deactivate());
  await waitFor(() => host.errors.length > 0, 'Port error was not reported');
  assert.match(host.state().connectionError, new RegExp(`Port ${port} is already used`));
  assert.equal(host.state().proxyConnected, false);
});

test('Add External MCP command saves a remote URL behind Guardian in the active settings', async t => {
  const host = extensionHost(await freePort());
  t.after(() => host.deactivate());
  host.inputQueue.push('docs', 'https://example.test/mcp', '{"Authorization":"Bearer ${env:MY_MCP_TOKEN}"}');
  await host.runCommand('mcp-guardian.addExternalServer');
  assert.equal(host.errors.length, 0);
  const server = host.state().config.servers.find(item => item.name === 'docs');
  assert.equal(server.type, 'http');
  assert.equal(server.url, 'https://example.test/mcp');
  assert.equal(server.headers.Authorization, 'Bearer ${env:MY_MCP_TOKEN}');
  assert.ok(host.information.some(message => message.includes('behind Guardian')));
});

test('Guard Workspace command imports direct MCPs, backs up config and leaves only the proxy', async t => {
  const host = extensionHost(await freePort(), true, true);
  t.after(() => host.deactivate());
  const mcpPath = path.join(host.storage, '.vscode', 'mcp.json');
  const original = '{ // preserve workspace comment\n "servers": {"docs.remote": {"type":"http","url":"https://example.test/mcp"}, "python": {"command":"python","args":["${workspaceFolder}/server.py"]}}, "inputs": [], }';
  fs.writeFileSync(mcpPath, original);
  await host.runCommand('mcp-guardian.guardWorkspaceServers');
  assert.equal(host.errors.length, 0);
  const parsed = require('jsonc-parser').parse(fs.readFileSync(mcpPath, 'utf8'));
  assert.deepEqual(Object.keys(parsed.servers), ['agent-guardian']);
  assert.deepEqual(parsed.inputs, []);
  assert.match(fs.readFileSync(mcpPath, 'utf8'), /preserve workspace comment/);
  const servers = host.state().config.servers;
  assert.equal(servers.find(item => item.name === 'docs_remote').url, 'https://example.test/mcp');
  assert.equal(servers.find(item => item.name === 'python').args[0], `${host.storage}/server.py`);
  assert.equal(servers.find(item => item.name === 'python').cwd, host.storage);
  const backup = fs.readdirSync(path.dirname(mcpPath)).find(name => name.startsWith('mcp.json.guardian-backup-'));
  assert.equal(fs.readFileSync(path.join(path.dirname(mcpPath), backup), 'utf8'), original);
  await host.runCommand('mcp-guardian.guardWorkspaceServers');
  assert.equal(host.errors.length, 0, 'Repeated routing should not import the proxy into itself');
});

test('workspace routing refuses unresolved interactive credentials before changing files', async t => {
  const host = extensionHost(await freePort(), true, true);
  t.after(() => host.deactivate());
  const mcpPath = path.join(host.storage, '.vscode', 'mcp.json');
  const original = JSON.stringify({ servers: { docs: { type: 'http', url: 'https://example.test/mcp', headers: { Authorization: 'Bearer ${input:token}' } } } });
  fs.writeFileSync(mcpPath, original);
  await host.runCommand('mcp-guardian.guardWorkspaceServers');
  assert.ok(host.errors.some(error => error.includes('interactive inputs')));
  assert.equal(fs.readFileSync(mcpPath, 'utf8'), original);
});

test('approvals go to their originating proxy and stay pending until authoritative acknowledgement', async t => {
  const port = await freePort();
  const host = extensionHost(port, true, false, true);
  t.after(() => host.deactivate());
  const first = new WebSocket(`ws://127.0.0.1:${port}`);
  const second = new WebSocket(`ws://127.0.0.1:${port}`);
  const receivedFirst = [], receivedSecond = [];
  first.on('message', value => receivedFirst.push(JSON.parse(value)));
  second.on('message', value => receivedSecond.push(JSON.parse(value)));
  t.after(() => { first.terminate(); second.terminate(); });
  await Promise.all([once(first, 'open'), once(second, 'open')]);
  const approval = { id: 'owned-by-first', actionFingerprint: 'a'.repeat(64), requestedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(), serverName: 'external', toolName: 'list_projects',
    capability: 'READ_NETWORK', sessionId: 'one', intent: 'Inspect', reason: 'Manual approval', arguments: {}, evidence: [] };
  const log = { id: approval.id, timestamp: approval.requestedAt, serverName: 'external', toolName: 'list_projects',
    category: 'READ_NETWORK', arguments: {}, status: 'pending', approval: { actionFingerprint: approval.actionFingerprint, expiresAt: approval.expiresAt } };
  first.send(JSON.stringify({ type: 'log', log }));
  first.send(JSON.stringify({ type: 'approve_request', approval }));
  await waitFor(() => host.state().pendingApprovals.length === 1, 'No approval displayed');
  second.send(JSON.stringify({ type: 'sync_state', baselines: {}, logs: [], config: host.state().config }));
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(host.state().pendingApprovals.length, 1, 'Unrelated snapshot erased the pending request');
  second.send(JSON.stringify({ type: 'log', log: { ...log, status: 'allow' } }));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(host.state().logs.some(item => item.id === approval.id && item.status === 'allow'), false, 'Another proxy forged an acknowledgement');
  host.sendWebview({ type: 'approve_request', id: approval.id, actionFingerprint: approval.actionFingerprint });
  await waitFor(() => receivedFirst.some(message => message.type === 'approve_response'), 'Reply never reached owner');
  assert.equal(receivedSecond.some(message => message.type === 'approve_response'), false);
  assert.equal(host.state().pendingApprovals[0].decisionSubmitted, true);
  assert.equal(host.state().logs.some(item => item.id === approval.id && item.status === 'allow'), false, 'False optimistic green');
  host.sendWebview({ type: 'approve_request', id: approval.id, actionFingerprint: approval.actionFingerprint });
  assert.equal(receivedFirst.filter(message => message.type === 'approve_response').length, 1);
  first.send(JSON.stringify({ type: 'log', log: { ...log, status: 'allow', reason: 'approved once by user' } }));
  await waitFor(() => host.state().pendingApprovals.length === 0 && host.state().logs.some(item => item.id === approval.id && item.status === 'allow'), 'Owner acknowledgement was not applied');
  second.close();
  await once(second, 'close');
  assert.equal(host.state().proxyConnected, true, 'Another connected client was incorrectly marked offline');
});

test('two real proxy processes can both complete approved calls on one dashboard', async t => {
  const host = extensionHost(await freePort());
  t.after(() => host.deactivate());
  const first = startProxy(host.env), second = startProxy(host.env);
  t.after(() => first.stop()); t.after(() => second.stop());
  await Promise.all([first.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} }), second.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} })]);
  await Promise.all([first.request('tools/list'), second.request('tools/list')]);
  const results = await Promise.all([first.request('tools/call', { name: 'dashboard-test__echo', arguments: { value: 'first' } }), second.request('tools/call', { name: 'dashboard-test__echo', arguments: { value: 'second' } })]);
  for (const result of results) assert.ok(result.result, JSON.stringify(result.error));
  assert.equal(host.approvals.length, 2);
});

test('large provider dashboard snapshots are delivered without relaxing external MCP limits', async t => {
  const host = extensionHost(await freePort());
  t.after(() => host.deactivate());
  const file = path.join(host.storage, 'mcp-guardian-db.json');
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  stored.baselines.bulk = { example: { name: 'example', description: 'Large reviewed metadata '.repeat(55000),
    hash: 'a'.repeat(64), category: 'GENERAL', approved: true, inputSchema: {}, status: 'approved' } };
  fs.writeFileSync(file, JSON.stringify(stored));
  const proxy = startProxy(host.env);
  t.after(() => proxy.stop());
  await waitFor(() => host.state().baselines.bulk?.example?.description.length > 1048576, 'Large sync_state was silently dropped');
  const initialized = await proxy.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  assert.ok(initialized.result);
  assert.equal(host.state().config.resourceLimits?.maxMessageBytes || 1048576, 1048576);
});

test('Guard Antigravity command imports the chosen raw config with matching dashboard settings', async t => {
  const host = extensionHost(await freePort());
  t.after(() => host.deactivate());
  const config = path.join(host.storage, 'mcp_config.json');
  fs.writeFileSync(config, JSON.stringify({ mcpServers: { external: { serverUrl: 'https://example.test/mcp' } } }));
  host.inputQueue.push(config);
  await host.runCommand('mcp-guardian.guardAntigravityServers');
  assert.equal(host.errors.length, 0, host.errors.join('\n'));
  const imported = JSON.parse(fs.readFileSync(config, 'utf8')).mcpServers;
  assert.deepEqual(Object.keys(imported), ['agent-guardian']);
  assert.equal(imported['agent-guardian'].command, 'node', 'An extension host executable is Electron, not node');
  assert.equal(imported['agent-guardian'].env.MCP_GUARDIAN_WS_PORT, host.env.MCP_GUARDIAN_WS_PORT);
  assert.equal(host.state().config.servers.find(server => server.name === 'external').url, 'https://example.test/mcp');
});

test('remote HTTP tool call completes through Guardian and the extension approval channel', async t => {
  let calls = 0;
  const remote = http.createServer(async (request, response) => {
    if (request.method !== 'POST') { response.writeHead(405); response.end(); return; }
    let body = '';
    for await (const chunk of request) body += chunk;
    const message = JSON.parse(body);
    if (message.id === undefined) { response.writeHead(202); response.end(); return; }
    let result;
    if (message.method === 'initialize') result = { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'remote-docs', version: '1' } };
    else if (message.method === 'tools/list') result = { tools: [{ name: 'search_docs', description: 'Search public technical documentation', inputSchema: { type: 'object' } }] };
    else { calls++; result = { content: [{ type: 'text', text: 'Public documentation' }] }; }
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }));
  });
  remote.listen(0, '127.0.0.1');
  await once(remote, 'listening');
  t.after(() => new Promise(resolve => { remote.closeAllConnections(); remote.close(resolve); }));
  const host = extensionHost(await freePort());
  t.after(() => host.deactivate());
  host.inputQueue.push('docs', `http://127.0.0.1:${remote.address().port}/mcp`, '{}');
  await host.runCommand('mcp-guardian.addExternalServer');
  const proxy = startProxy(host.env);
  t.after(() => proxy.stop());
  await waitFor(() => host.state().proxyConnected, 'Remote proxy did not connect to approval UI');
  assert.ok((await proxy.request('initialize', { protocolVersion: '2024-11-05', capabilities: {} })).result);
  await proxy.request('tools/list');
  await waitFor(() => host.state().baselines.docs?.search_docs, 'Remote metadata never updated Security Rules');
  assert.equal(calls, 0);
  const response = await proxy.request('tools/call', { name: 'docs__search_docs', arguments: { query: 'Node.js' } });
  assert.ok(response.result, JSON.stringify(response.error));
  assert.equal(host.approvals.length, 1);
  assert.equal(calls, 1);
  await waitFor(() => host.state().logs.some(log => log.serverName === 'docs' && log.status === 'allow'), 'Remote approval was not logged');
  assert.equal(host.state().logs.find(log => log.serverName === 'docs').category, 'READ_NETWORK');
  assert.equal(host.state().pendingApprovals.length, 0);
  const dbPath = path.join(host.storage, 'mcp-guardian-db.json');
  assert.ok(JSON.parse(fs.readFileSync(dbPath, 'utf8')).baselines.docs.search_docs,
    'Extension overwrote the remote baseline after receiving an audit log');
  host.sendWebview({ type: 'clear_logs' });
  await waitFor(() => host.state().logs.length === 0, 'Clear did not synchronize with the proxy');
  await host.runCommand('mcp-guardian.refreshDashboard');
  assert.equal(host.state().logs.length, 0, 'Refresh restored previously cleared history');
});
