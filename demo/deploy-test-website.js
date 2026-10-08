// User-requested isolated preview deployment THROUGH Guardian, not Vercel CLI.
// Fixed target/files only. No OAuth credentials are read by this script.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const { spawn, execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const website = path.resolve(root, '../Guardian_Test_Website');
const storage = path.join(root, '.mcp-guardian/vercel-website-deployment');
const reportDir = path.join(website, 'test-output');
const teamIndex = process.argv.indexOf('--team');
const teamId = teamIndex >= 0 ? process.argv[teamIndex + 1] : undefined;
assert.ok(teamId && /^team_[a-zA-Z0-9]+$/.test(teamId), 'Supply the explicitly verified --team <team-id>; never use an implicit default');
const projectName = 'agent-guardian-test-website';
const inspectOnly = process.argv.includes('--inspect');
if (!process.argv.includes('--deploy') && !inspectOnly) throw new Error('Explicit --deploy or --inspect required');
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: website, encoding: 'utf8' }).trim();
assert.equal(execFileSync('git', ['status', '--porcelain'], { cwd: website, encoding: 'utf8' }).trim(), '', 'Commit website changes before deployment');
const files = ['index.html', 'receipt.html', 'style.css'].map(file => ({ file, data: fs.readFileSync(path.join(website, file), 'utf8'), encoding: 'utf-8' }));
fs.mkdirSync(storage, { recursive: true }); fs.mkdirSync(reportDir, { recursive: true });
// Narrow, out-of-band authorization for this scripted demo. This does not
// change the IDE's manual approvals; unknown/destructive operations are never called.
const config = { servers: [{ name: 'vercel', command: 'cmd', args: ['/c', 'npx', '-y', 'mcp-remote@0.14.3', 'https://mcp.vercel.com'],
    env: { MCP_REMOTE_CONFIG_DIR: path.join(root, '.mcp-guardian/vercel-oauth') } }],
  autoApproveSafe: true, forbiddenTransitions: [], resourceLimits: { requestTimeoutMs: 60000 },
  sessionPolicy: { intent: `Create only ${projectName} in ${teamId} and deploy these three committed static files as preview; never alter existing projects or production`,
    allowedCapabilities: ['READ_LOCAL', 'READ_NETWORK', 'WRITE_COMMUNICATION'], trustedDestinations: [] } };
const dbFile = path.join(storage, 'mcp-guardian-db.json');
const previous = fs.existsSync(dbFile) ? JSON.parse(fs.readFileSync(dbFile, 'utf8')) : { baselines: {}, logs: [] };
fs.writeFileSync(dbFile, JSON.stringify({ ...previous, config }));
const child = spawn(process.execPath, [path.join(root, 'dist/cli.js'), 'proxy'], { cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, MCP_GUARDIAN_STORAGE_PATH: storage, MCP_GUARDIAN_WS_DISABLED: '1', MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: '' } });
child.stderr.on('data', data => {
  for (const line of data.toString().split('\n').filter(line => line.startsWith('[MCP-Guardian-Proxy]'))) console.error(line);
});
let sequence = 0;
const pending = new Map();
const reader = readline.createInterface({ input: child.stdout });
reader.on('line', line => { const message = JSON.parse(line); pending.get(message.id)?.(message); });
function request(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 90000);
    pending.set(id, message => { clearTimeout(timer); pending.delete(id); resolve(message); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
const allowed = new Set(['get_team', 'list_projects', 'create_project', 'create_deployment', 'get_deployment', 'list_deployments']);
async function call(tool, args) {
  assert.ok(allowed.has(tool), 'Operation not authorized for this demo');
  assert.equal(args.teamId, teamId, 'Every operation must be scoped to the verified test team');
  const response = await request('tools/call', { name: `vercel__${tool}`, arguments: args });
  assert.ok(response.result && !response.result.isError, JSON.stringify(response.error || response.result));
  const text = response.result.content?.find(item => item.type === 'text')?.text;
  const parsed = response.result.structuredContent || JSON.parse(text);
  fs.writeFileSync(path.join(reportDir, `response-${tool}.json`), JSON.stringify(parsed, null, 2));
  if (parsed.error) throw new Error(JSON.stringify(parsed.error));
  const value = parsed.result || parsed;
  if (['create_deployment', 'get_deployment'].includes(tool)) return value.deployment || value;
  if (tool === 'list_deployments' && value.deployments && !Array.isArray(value.deployments)) return value.deployments;
  return value;
}
(async () => {
  const initialized = await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'guardian-test-website-deployment', version: '1' } });
  assert.ok(initialized.result, JSON.stringify(initialized.error));
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const listed = await request('tools/list'); assert.ok(listed.result, JSON.stringify(listed.error));
  for (const tool of allowed) assert.ok(listed.result.tools.some(item => item.name === `vercel__${tool}`), `${tool} unavailable or rejected; stop`);
  const team = await call('get_team', { teamId });
  assert.equal(team.id || team.team?.id, teamId);
  console.log(`Verified test team: ${team.slug || team.team?.slug || teamId}`);
  const projects = await call('list_projects', { teamId, search: projectName, limit: '10' });
  let project = projects.projects?.find(item => item.name === projectName);
  if (inspectOnly) {
    assert.ok(project, 'No matching demo project');
    const deployments = await call('list_deployments', { teamId, projectId: project.id, limit: 5 });
    console.log(JSON.stringify({ projectId: project.id, deployments }, null, 2));
    const latest = deployments.deployments?.[0];
    if (latest) {
      const actual = await call('get_deployment', { teamId, idOrUrl: latest.id });
      const database = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
      const report = { teamId, projectId: project.id, projectName, deploymentId: actual.id || latest.id,
        url: `https://${actual.url || latest.url}`, target: actual.target || latest.target || 'preview',
        status: actual.readyState || latest.state, websiteCommit: commit,
        files: files.map(file => ({ file: file.file, sha256: crypto.createHash('sha256').update(file.data).digest('hex') })),
        guardianStorage: storage, route: 'client → Guardian → mcp-remote → Vercel MCP',
        note: 'First deployment of the new demo project was automatically marked production by Vercel; no existing projects were changed.' };
      fs.writeFileSync(path.join(reportDir, 'deployment.json'), JSON.stringify(report, null, 2));
      fs.writeFileSync(path.join(reportDir, 'guardian-audit.json'), require('../dist/reporting.js').serializeReport(database.logs, 'json'));
      console.log(JSON.stringify(report, null, 2));
    }
    return;
  }
  if (!project) {
    project = await call('create_project', { teamId, requestBody: { name: projectName, framework: null } });
    console.log(`Created isolated project: ${project.id}`);
  }
  assert.equal(project.name, projectName); assert.equal(project.accountId, teamId);
  const deployment = await call('create_deployment', { teamId, requestBody: { name: projectName, project: project.id, files, target: 'staging',
    projectSettings: { framework: null, buildCommand: null, installCommand: null, outputDirectory: null },
    meta: { guardianWebsiteCommit: commit, guardianTest: 'isolated-preview' } } });
  assert.ok(deployment.id && deployment.url, `Deployment response lacked ID/URL: ${JSON.stringify(deployment).slice(0, 2500)}`);
  const report = { teamId, projectId: project.id, projectName, deploymentId: deployment.id, url: `https://${deployment.url}`,
    target: deployment.target || 'preview', status: deployment.readyState, websiteCommit: commit,
    files: files.map(file => ({ file: file.file, sha256: crypto.createHash('sha256').update(file.data).digest('hex') })),
    guardianStorage: storage, route: 'client → Guardian → mcp-remote → Vercel MCP' };
  fs.writeFileSync(path.join(reportDir, 'deployment.json'), JSON.stringify(report, null, 2));
  assert.notEqual(report.target, 'production', 'Unexpected production target; do not promote');
  console.log(JSON.stringify(report, null, 2));
  // Repeated read-only inspection is allowed while an asynchronous build changes state.
  for (let attempt = 0; attempt < 6; attempt++) {
    const inspected = await call('get_deployment', { teamId, idOrUrl: deployment.id });
    report.status = inspected.readyState || inspected.status;
    fs.writeFileSync(path.join(reportDir, 'deployment.json'), JSON.stringify(report, null, 2));
    console.log(`Deployment status: ${report.status}`);
    if (report.status === 'READY') break;
    if (['ERROR', 'CANCELED'].includes(report.status)) throw new Error(`Deployment ${report.status}`);
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
  assert.equal(report.status, 'READY', 'Deployment not confirmed READY');
  const database = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  assert.ok(database.logs.some(log => log.toolName === 'create_deployment' && log.status === 'allow'));
  fs.writeFileSync(path.join(reportDir, 'guardian-audit.json'), require('../dist/reporting.js').serializeReport(database.logs, 'json'));
  console.log(`PASS: guarded preview deployment ready at ${report.url}`);
})().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => { child.stdin.end(); reader.close(); });
