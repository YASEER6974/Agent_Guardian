import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { WebSocketServer, WebSocket } from 'ws';
import { GuardianDb } from './db';
import { readWorkspaceSettings } from './workspace-settings';
import { validateServer } from './server-config';
import { routeAntigravityServers, routeWorkspaceServers, saveExternalServer } from './connection-config';
import { parse } from 'jsonc-parser/lib/esm/main';
import { DownstreamServerConfig } from './types';
import { GuardianConfig, ExtensionMessage, ProxyMessage, AuditLog, ApprovalRequestView } from './types';
import { ReportFormat, serializeReport } from './reporting';
import { CrossSurfaceRecord, CrossSurfaceStore } from './browser/cross-surface-store';

let wss: WebSocketServer | null = null;
let activeProxySocket: WebSocket | null = null;
const proxySockets = new Set<WebSocket>();
const approvalOwners = new Map<string, WebSocket>();
const submittedApprovals = new Set<string>();
let db: GuardianDb;
let crossSurfaceStore: CrossSurfaceStore;
let webviewPanel: vscode.WebviewView | null = null;
const pendingApprovalViews = new Map<string, ApprovalRequestView>();
let connectionPort = 1337;
let connectionError: string | undefined;
let workspaceSettingsPath: string | undefined;
let runtimeStoragePath: string;
let stopBrowserTraceWatch: (() => void) | undefined;

export function activate(context: vscode.ExtensionContext) {
  console.log('MCP Guardian is active.');

  // The extension and its proxy must use the same store. A development host
  // can override this path so another VS Code window cannot replace its config.
  const runtimeSettings = vscode.workspace.getConfiguration('mcp-guardian');
  const developmentSettingsPath = path.join(context.extensionUri.fsPath, '.vscode', 'settings.json');
  workspaceSettingsPath = process.env.MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH ||
    (context.extensionMode === vscode.ExtensionMode.Development && fs.existsSync(developmentSettingsPath)
      ? developmentSettingsPath : undefined);
  const launchSettings: Record<string, unknown> = workspaceSettingsPath
    ? parse(fs.readFileSync(workspaceSettingsPath, 'utf8'), [], { allowTrailingComma: true }) : {};
  const launchStorage = typeof launchSettings['mcp-guardian.storagePath'] === 'string'
    ? launchSettings['mcp-guardian.storagePath'] as string : undefined;
  const storagePath = process.env.MCP_GUARDIAN_STORAGE_PATH || launchStorage || runtimeSettings.get<string>('storagePath') || path.join(os.homedir(), '.mcp-guardian');
  runtimeStoragePath = storagePath;
  db = new GuardianDb(storagePath);
  crossSurfaceStore = new CrossSurfaceStore(storagePath);
  const browserTracePath = path.join(storagePath, 'cross-surface-events.jsonl');
  const updateBrowserTrace = () => syncStateToWebview();
  fs.watchFile(browserTracePath, { interval: 1_000, persistent: false }, updateBrowserTrace);
  stopBrowserTraceWatch = () => fs.unwatchFile(browserTracePath, updateBrowserTrace);
  context.subscriptions.push({ dispose: stopBrowserTraceWatch });

  // Sync extension config with VS Code settings
  syncSettingsFromVscode();

  // Listen to configuration changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('mcp-guardian')) {
        syncSettingsFromVscode();
      }
    })
  );

  for (const [command, format] of [
    ['mcp-guardian.exportAuditJson', 'json'],
    ['mcp-guardian.exportAuditJsonl', 'jsonl'],
    ['mcp-guardian.exportAuditSarif', 'sarif']
  ] as Array<[string, ReportFormat]>) {
    context.subscriptions.push(vscode.commands.registerCommand(command, () => exportAuditReport(format)));
  }

  // Start WebSocket Server
  const wsPort = Number(process.env.MCP_GUARDIAN_WS_PORT) || Number(launchSettings['mcp-guardian.wsPort']) || runtimeSettings.get<number>('wsPort') || 1337;
  startWebSocketServer(wsPort);
  registerGuardianMcpServer(context, storagePath, wsPort);
  context.subscriptions.push(vscode.commands.registerCommand('mcp-guardian.addExternalServer', () => addExternalServer()));
  context.subscriptions.push(vscode.commands.registerCommand('mcp-guardian.guardWorkspaceServers', () => guardWorkspaceServers(context)));
  context.subscriptions.push(vscode.commands.registerCommand('mcp-guardian.guardAntigravityServers', () => guardAntigravityServers(context)));

  // Register Webview Provider
  const provider = new GuardianWebviewProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('mcp-guardian.dashboard', provider, { webviewOptions: { retainContextWhenHidden: true } })
  );

  // Register Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.refreshDashboard', () => refreshDashboard())
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.openDashboard', () => {
      vscode.commands.executeCommand('workbench.view.extension.mcp-guardian-explorer');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.approveTool', (logId: string) => {
      respondToPendingRequest(logId, true);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.denyTool', (logId: string) => {
      respondToPendingRequest(logId, false);
    })
  );
}

export function deactivate() {
  stopBrowserTraceWatch?.();
  stopBrowserTraceWatch = undefined;
  for (const socket of proxySockets) socket.close();
  proxySockets.clear();
  approvalOwners.clear();
  submittedApprovals.clear();
  pendingApprovalViews.clear();
  if (wss) {
    wss.close();
    wss = null;
  }
}

async function addExternalServer(): Promise<void> {
  try {
    const type = await vscode.window.showQuickPick([
      { label: 'Remote HTTP MCP', description: 'Connect a hosted MCP endpoint through Guardian', type: 'http' },
      { label: 'Local stdio MCP', description: 'Run an external Node.js or Python MCP server through Guardian', type: 'stdio' }
    ], { title: 'Agent Guardian: Add external MCP server' });
    if (!type) return;
    const name = await vscode.window.showInputBox({ title: 'External MCP server name', prompt: 'Letters, numbers, underscores and hyphens', value: type.type === 'http' ? 'microsoft-learn' : 'external-server', ignoreFocusOut: true });
    if (!name) return;
    let server: DownstreamServerConfig;
    if (type.type === 'http') {
      const url = await vscode.window.showInputBox({ title: 'Remote MCP endpoint', prompt: 'The Streamable HTTP MCP URL', value: 'https://learn.microsoft.com/api/mcp', ignoreFocusOut: true });
      if (!url) return;
      const headersText = await vscode.window.showInputBox({ title: 'Optional HTTP headers as JSON', prompt: 'Use ${env:TOKEN_NAME} for credentials; {} for a public endpoint', value: '{}', ignoreFocusOut: true });
      if (headersText === undefined) return;
      const headers = JSON.parse(headersText);
      server = validateServer({ name, type: 'http', url, ...(Object.keys(headers).length ? { headers } : {}) });
    } else {
      const command = await vscode.window.showInputBox({ title: 'External MCP command', prompt: 'For example: node, python, or cmd', ignoreFocusOut: true });
      if (!command) return;
      const args = await vscode.window.showInputBox({ title: 'Arguments as a JSON array', value: '[]', ignoreFocusOut: true });
      if (args === undefined) return;
      server = validateServer({ name, command, args: JSON.parse(args) });
    }
    if (workspaceSettingsPath) {
      saveExternalServer(workspaceSettingsPath, server);
      syncSettingsFromVscode();
    } else {
      const servers = [...db.getConfig().servers.filter(item => item.name !== server.name), server];
      await vscode.workspace.getConfiguration('mcp-guardian').update('servers', servers,
        vscode.workspace.workspaceFolders?.length ? vscode.ConfigurationTarget.Workspace : vscode.ConfigurationTarget.Global);
      db.updateConfig({ servers });
      sendToProxy({ type: 'update_config', config: db.getConfig() });
      syncStateToWebview();
    }
    void vscode.window.showInformationMessage(`Added ${server.name} behind Guardian. Start or refresh agent-guardian in MCP: List Servers; do not add the endpoint as a separate direct server.`);
  } catch (error) { void vscode.window.showErrorMessage(`Agent Guardian: ${error instanceof Error ? error.message : 'Cannot add server'}`); }
}

async function guardWorkspaceServers(context: vscode.ExtensionContext): Promise<void> {
  try {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ||
      (workspaceSettingsPath ? path.dirname(path.dirname(workspaceSettingsPath)) : undefined);
    if (!workspaceRoot) throw new Error('Open the workspace whose MCP servers should be routed through Guardian');
    const result = routeWorkspaceServers(workspaceRoot, {
      type: 'stdio', command: 'node', args: [path.join(context.extensionUri.fsPath, 'dist', 'cli.js'), 'proxy'],
      env: {
        MCP_GUARDIAN_STORAGE_PATH: runtimeStoragePath, MCP_GUARDIAN_WS_PORT: String(connectionPort),
        MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: path.join(workspaceRoot, '.vscode', 'settings.json')
      }
    });
    workspaceSettingsPath = path.join(workspaceRoot, '.vscode', 'settings.json');
    syncSettingsFromVscode();
    void vscode.window.showInformationMessage(`Routed ${result.imported} external MCP servers through agent-guardian. Restart previous direct servers to remove their old connections.${result.backup ? ` Backup: ${result.backup}` : ''}`);
  } catch (error) { void vscode.window.showErrorMessage(`Agent Guardian: ${error instanceof Error ? error.message : 'Cannot route servers'}`); }
}

async function guardAntigravityServers(context: vscode.ExtensionContext): Promise<void> {
  try {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ||
      (workspaceSettingsPath ? path.dirname(path.dirname(workspaceSettingsPath)) : undefined);
    if (!workspaceRoot) throw new Error('Open the Guardian workspace first');
    const selected = await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFolders: false,
      title: 'Select Antigravity MCP config (the file opened by View raw config)', filters: { JSON: ['json'] } });
    if (!selected?.[0]) return;
    const settingsPath = path.join(workspaceRoot, '.vscode', 'settings.json');
    const result = routeAntigravityServers(selected[0].fsPath, workspaceRoot, {
      command: 'node', args: [path.join(context.extensionUri.fsPath, 'dist', 'cli.js'), 'proxy'], cwd: workspaceRoot,
      env: { MCP_GUARDIAN_STORAGE_PATH: runtimeStoragePath, MCP_GUARDIAN_WS_PORT: String(connectionPort),
        MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: settingsPath }
    }, { 'mcp-guardian.storagePath': runtimeStoragePath, 'mcp-guardian.wsPort': connectionPort });
    workspaceSettingsPath = settingsPath;
    syncSettingsFromVscode();
    void vscode.window.showInformationMessage(`Routed ${result.imported} Antigravity MCP servers through Guardian. Backup: ${result.backup}. Stop direct servers and refresh Antigravity's MCP manager.`);
  } catch (error) { void vscode.window.showErrorMessage(`Agent Guardian: ${error instanceof Error ? error.message : 'Cannot route Antigravity servers'}`); }
}

function syncSettingsFromVscode() {
  const config = vscode.workspace.getConfiguration('mcp-guardian');
  const servers = config.get<any[]>('servers') || [];
  const forbiddenTransitions = config.get<[string, string][]>('forbiddenTransitions') || [];
  const geminiApiKey = config.get<string>('geminiApiKey') || '';
  const autoApproveSafe = config.get<boolean>('autoApproveSafe') ?? true;
  const intent = config.get<string>('sessionIntent') || '';
  const allowedCapabilities = config.get<string[]>('allowedCapabilities') || [];
  const trustedDestinations = config.get<string[]>('trustedDestinations') || [];

  db.updateConfig({
    servers,
    forbiddenTransitions,
    geminiApiKey,
    autoApproveSafe,
    sessionPolicy: { intent, allowedCapabilities, trustedDestinations }
  });

  if (workspaceSettingsPath) db.updateConfig(readWorkspaceSettings(workspaceSettingsPath, db.getConfig()));

  // Sync to proxy
  sendToProxy({
    type: 'update_config',
    config: db.getConfig()
  });
  syncStateToWebview();
}

function startWebSocketServer(port: number) {
  connectionPort = port;
  connectionError = undefined;
  try {
    wss = new WebSocketServer({ port, host: '127.0.0.1', maxPayload: 16_777_216 });
    wss.on('listening', () => {
      console.log(`WebSocket server started on ws://127.0.0.1:${port}`);
      syncStateToWebview();
    });
    wss.on('error', (error: NodeJS.ErrnoException) => {
      connectionError = error.code === 'EADDRINUSE'
        ? `Port ${port} is already used by another window. Close that Guardian host or use a matching free port for the extension and proxy.`
        : `Dashboard connection failed on port ${port}: ${error.message}`;
      console.error(connectionError);
      void vscode.window.showErrorMessage(`[Agent Guardian] ${connectionError}`);
      syncStateToWebview();
    });

    wss.on('connection', (ws) => {
      console.log('Proxy connected to WS server');
      activeProxySocket = ws;
      proxySockets.add(ws);
      connectionError = undefined;
      syncStateToWebview();

      // Push the authoritative VS Code configuration as soon as the proxy
      // connects. The proxy and extension share the on-disk audit store, but
      // the proxy still needs an update_config message to restart downstream
      // servers when workspace settings override the global configuration.
      ws.send(JSON.stringify({
        type: 'update_config',
        config: db.getConfig()
      }));

      ws.on('message', (message) => {
        try {
          const data: ProxyMessage = JSON.parse(message.toString());
          handleProxyMessage(data, ws);
        } catch (e) {
          console.error('Failed to parse message from proxy:', e);
        }
      });

      ws.on('close', () => {
        console.log('Proxy disconnected');
        proxySockets.delete(ws);
        for (const [id, owner] of approvalOwners) {
          if (owner === ws) {
            approvalOwners.delete(id);
            submittedApprovals.delete(id);
            pendingApprovalViews.delete(id);
          }
        }
        if (activeProxySocket === ws) {
          activeProxySocket = Array.from(proxySockets).find(socket => socket.readyState === WebSocket.OPEN) || null;
        }
        syncStateToWebview();
      });
      ws.on('error', (error) => console.error('Proxy connection error:', error));
    });
  } catch (err) {
    console.error('Failed to start WebSocket server:', err);
  }
}

function sendToProxy(msg: ExtensionMessage) {
  for (const socket of proxySockets) if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(msg));
}

function handleProxyMessage(msg: ProxyMessage, source: WebSocket) {
  switch (msg.type) {
    case 'sync_state':
      const incomingLogs = msg.logs.filter(log => !approvalOwners.has(log.id) || approvalOwners.get(log.id) === source);
      for (const existing of db.getLogs()) {
        if (approvalOwners.has(existing.id) && approvalOwners.get(existing.id) !== source) incomingLogs.push(existing);
      }
      db.mirrorState({ baselines: msg.baselines, logs: incomingLogs, config: msg.config });
      for (const [id] of pendingApprovalViews) {
        if (approvalOwners.get(id) === source && msg.logs.some(log => log.id === id && log.status !== 'pending')) {
          pendingApprovalViews.delete(id);
          approvalOwners.delete(id);
          submittedApprovals.delete(id);
        }
      }
      // Sync to Webview UI
      syncStateToWebview();
      break;

    case 'log':
      if (approvalOwners.has(msg.log.id) && approvalOwners.get(msg.log.id) !== source) return;
      db.mirrorLog(msg.log);
      if (msg.log.status !== 'pending' && approvalOwners.get(msg.log.id) === source) {
        pendingApprovalViews.delete(msg.log.id);
        approvalOwners.delete(msg.log.id);
        submittedApprovals.delete(msg.log.id);
      }
      syncStateToWebview();
      break;

    case 'downstream_status':
      // Sync status log to Webview
      syncStateToWebview();
      break;

    case 'approve_request': {
      // Intercepted tool call. Show interactive notification alert
      const approval = msg.approval;
      if (approvalOwners.has(approval.id) && approvalOwners.get(approval.id) !== source) return;
      approvalOwners.set(approval.id, source);
      pendingApprovalViews.set(approval.id, approval);
      
      // Update UI first
      syncStateToWebview();

      // Show native VS Code dialog notification
      vscode.window.showWarningMessage(
        `[Agent Guardian] ${approval.serverName}__${approval.toolName} (${approval.capability}) wants approval once. Intent: ${approval.intent}. Destination: ${approval.destination || 'none'}. Reason: ${approval.reason}`,
        'Approve Once',
        'Deny'
      ).then((selection) => {
        if (selection === 'Approve Once') {
          respondToPendingRequest(approval.id, true, approval.actionFingerprint);
        } else {
          respondToPendingRequest(approval.id, false, approval.actionFingerprint);
        }
      });
      break;
    }
  }
}

function respondToPendingRequest(logId: string, approved: boolean, suppliedFingerprint?: string) {
  const approval = pendingApprovalViews.get(logId);
  const owner = approvalOwners.get(logId);
  if (!approval || !owner || owner.readyState !== WebSocket.OPEN || submittedApprovals.has(logId)) return;
  const fingerprint = suppliedFingerprint || approval.actionFingerprint;
  if (fingerprint !== approval.actionFingerprint || Date.parse(approval.expiresAt) <= Date.now()) return;
  submittedApprovals.add(logId);
  // The owning proxy validates action/expiry. Never display optimistic ALLOW.
  owner.send(JSON.stringify({
    type: 'approve_response',
    id: logId,
    actionFingerprint: fingerprint,
    approved
  } satisfies ExtensionMessage));

  // Sync updated state to Webview
  syncStateToWebview();
}

function refreshDashboard() {
  if (activeProxySocket?.readyState === WebSocket.OPEN) sendToProxy({ type: 'request_state' });
  else db.refresh();
  syncStateToWebview();
}

function syncStateToWebview() {
  if (webviewPanel) {
    let crossSurfaceRecords: CrossSurfaceRecord[] = [];
    let traceIntegrity = true;
    try {
      crossSurfaceRecords = crossSurfaceStore.list(undefined, 200);
    } catch {
      traceIntegrity = false;
    }
    webviewPanel.webview.postMessage({
      type: 'sync',
      baselines: db.getBaselines(),
      logs: db.getLogs(),
      config: db.getConfig(),
      proxyConnected: activeProxySocket?.readyState === WebSocket.OPEN,
      connectionPort,
      connectionError,
      crossSurfaceRecords,
      traceIntegrity,
      pendingApprovals: Array.from(pendingApprovalViews.values())
        .filter(item => Date.parse(item.expiresAt) > Date.now())
        .map(item => ({ ...item, decisionSubmitted: submittedApprovals.has(item.id) }))
    });
  }
}

// VS Code Webview View Provider
class GuardianWebviewProvider implements vscode.WebviewViewProvider {
  constructor(private readonly extensionUri: vscode.Uri) {}

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext<unknown>,
    token: vscode.CancellationToken
  ): void | Thenable<void> {
    webviewPanel = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.extensionUri]
    };

    webviewView.webview.html = this.getHtmlContent(webviewView.webview);

    // Listen to messages from the UI
    webviewView.webview.onDidReceiveMessage((message) => {
      switch (message.type) {
        case 'request_sync':
          refreshDashboard();
          break;
        case 'add_external_server':
          void addExternalServer();
          break;
        case 'guard_workspace_servers':
          void vscode.commands.executeCommand('mcp-guardian.guardWorkspaceServers');
          break;
        case 'guard_antigravity_servers':
          void vscode.commands.executeCommand('mcp-guardian.guardAntigravityServers');
          break;
        case 'approve_request':
          respondToPendingRequest(message.id, true, message.actionFingerprint);
          break;
        case 'deny_request':
          respondToPendingRequest(message.id, false, message.actionFingerprint);
          break;
        case 'approve_drift':
          sendToProxy({
            type: 'approve_drift',
            serverName: message.serverName,
            toolName: message.toolName,
            newHash: message.newHash
          });
          break;
        case 'set_category':
          sendToProxy({
            type: 'set_category',
            serverName: message.serverName,
            toolName: message.toolName,
            category: message.category
          });
          break;
        case 'save_config':
          // Save to VS Code configuration so it persists
          const config = vscode.workspace.getConfiguration('mcp-guardian');
          config.update('servers', message.config.servers, vscode.ConfigurationTarget.Global);
          config.update('forbiddenTransitions', message.config.forbiddenTransitions, vscode.ConfigurationTarget.Global);
          config.update('geminiApiKey', message.config.geminiApiKey, vscode.ConfigurationTarget.Global);
          config.update('autoApproveSafe', message.config.autoApproveSafe, vscode.ConfigurationTarget.Global);
          config.update('sessionIntent', message.config.sessionPolicy?.intent || '', vscode.ConfigurationTarget.Global);
          config.update('allowedCapabilities', message.config.sessionPolicy?.allowedCapabilities || [], vscode.ConfigurationTarget.Global);
          config.update('trustedDestinations', message.config.sessionPolicy?.trustedDestinations || [], vscode.ConfigurationTarget.Global);
          break;
        case 'export_report':
          void exportAuditReport(message.format);
          break;
        case 'clear_logs':
          if (activeProxySocket?.readyState === WebSocket.OPEN) sendToProxy({ type: 'clear_logs' });
          else { db.clearLogs(); syncStateToWebview(); }
          break;
      }
    });

    // Handle view state changes
    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) {
        refreshDashboard();
      }
    });

    // Send initial sync
    setTimeout(refreshDashboard, 500);
  }

  private getHtmlContent(webview: vscode.Webview): string {
    const htmlPath = path.join(this.extensionUri.fsPath, 'src', 'webview', 'sidebar.html');
    if (fs.existsSync(htmlPath)) {
      let content = fs.readFileSync(htmlPath, 'utf8');
      
      // Inject VS Code Webview CSP and standard vscode CSS/JS hooks if needed
      // (For now, our embedded sidebar will be clean and self-contained)
      return content;
    }
    return `<html><body><h3>Failed to load Dashboard UI at ${htmlPath}</h3></body></html>`;
  }
}

function registerGuardianMcpServer(context: vscode.ExtensionContext, storagePath: string, port: number) {
  // Older editors can continue using an explicit MCP configuration file.
  if (!vscode.lm?.registerMcpServerDefinitionProvider || !vscode.McpStdioServerDefinition) return;
  context.subscriptions.push(vscode.lm.registerMcpServerDefinitionProvider('mcp-guardian.proxy', {
    provideMcpServerDefinitions: () => {
      // Do not offer a second proxy when this workspace already configures one.
      const configured = (vscode.workspace.workspaceFolders || []).some(folder => {
        try {
          const config = parse(fs.readFileSync(path.join(folder.uri.fsPath, '.vscode', 'mcp.json'), 'utf8'), [], { allowTrailingComma: true });
          return Boolean(config.servers?.['agent-guardian'] || config.servers?.['mcp-guardian']);
        } catch {
          return false;
        }
      });
      if (configured) return [];
      const env: Record<string, string> = {
        MCP_GUARDIAN_STORAGE_PATH: storagePath,
        MCP_GUARDIAN_WS_PORT: String(port),
        MCP_GUARDIAN_WS_DISABLED: '0',
        ...(workspaceSettingsPath ? { MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH: workspaceSettingsPath } : {})
      };
      const server = new vscode.McpStdioServerDefinition(
        'agent-guardian', 'node', [path.join(context.extensionUri.fsPath, 'dist', 'cli.js'), 'proxy'], env
      );
      server.cwd = context.extensionUri;
      return [server];
    }
  }));
}

async function exportAuditReport(format: ReportFormat): Promise<void> {
  const extension = format === 'sarif' ? 'sarif' : format;
  const target = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(path.join(os.homedir(), `agent-guardian-audit.${extension}`)),
    filters: { 'Agent Guardian audit': [extension] },
    saveLabel: `Export ${format.toUpperCase()}`
  });
  if (!target) return;
  await vscode.workspace.fs.writeFile(target, Buffer.from(serializeReport(db.getLogs(), format), 'utf8'));
  void vscode.window.showInformationMessage(`Agent Guardian audit exported to ${target.fsPath}`);
}
