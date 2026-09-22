import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { WebSocketServer, WebSocket } from 'ws';
import { GuardianDb } from './db';
import { GuardianConfig, ExtensionMessage, ProxyMessage, AuditLog, ApprovalRequestView } from './types';
import { ReportFormat, serializeReport } from './reporting';
import { CrossSurfaceRecord, CrossSurfaceStore } from './browser/cross-surface-store';

let wss: WebSocketServer | null = null;
let activeProxySocket: WebSocket | null = null;
let db: GuardianDb;
let crossSurfaceStore: CrossSurfaceStore;
let webviewPanel: vscode.WebviewView | null = null;
const pendingApprovalViews = new Map<string, ApprovalRequestView>();

export function activate(context: vscode.ExtensionContext) {
  console.log('MCP Guardian is active.');

  // The extension and its proxy must use the same store. A development host
  // can override this path so another VS Code window cannot replace its config.
  const runtimeSettings = vscode.workspace.getConfiguration('mcp-guardian');
  const storagePath = runtimeSettings.get<string>('storagePath') || process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
  db = new GuardianDb(storagePath);
  crossSurfaceStore = new CrossSurfaceStore(storagePath);

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
  const wsPort = runtimeSettings.get<number>('wsPort') || Number(process.env.MCP_GUARDIAN_WS_PORT) || 1337;
  startWebSocketServer(wsPort);

  // Register Webview Provider
  const provider = new GuardianWebviewProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('mcp-guardian.dashboard', provider)
  );

  // Register Commands
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
  if (wss) {
    wss.close();
  }
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

  // Sync to proxy
  sendToProxy({
    type: 'update_config',
    config: db.getConfig()
  });
}

function startWebSocketServer(port: number) {
  try {
    wss = new WebSocketServer({ port });
    console.log(`WebSocket server started on ws://localhost:${port}`);

    wss.on('connection', (ws) => {
      console.log('Proxy connected to WS server');
      activeProxySocket = ws;

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
          handleProxyMessage(data);
        } catch (e) {
          console.error('Failed to parse message from proxy:', e);
        }
      });

      ws.on('close', () => {
        console.log('Proxy disconnected');
        if (activeProxySocket === ws) {
          activeProxySocket = null;
        }
      });
    });
  } catch (err) {
    console.error('Failed to start WebSocket server:', err);
  }
}

function sendToProxy(msg: ExtensionMessage) {
  if (activeProxySocket && activeProxySocket.readyState === WebSocket.OPEN) {
    activeProxySocket.send(JSON.stringify(msg));
  }
}

function handleProxyMessage(msg: ProxyMessage) {
  switch (msg.type) {
    case 'sync_state':
      // Update database baselines
      for (const [serverName, serverTools] of Object.entries(msg.baselines)) {
        for (const [toolName, baseline] of Object.entries(serverTools)) {
          db.setToolBaseline(serverName, toolName, baseline);
        }
      }
      // Sync to Webview UI
      syncStateToWebview();
      break;

    case 'log':
      db.addLog(msg.log);
      syncStateToWebview();
      break;

    case 'downstream_status':
      // Sync status log to Webview
      syncStateToWebview();
      break;

    case 'approve_request': {
      // Intercepted tool call. Show interactive notification alert
      const approval = msg.approval;
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
  // Update local log status
  const logs = db.getLogs();
  const logIndex = logs.findIndex(l => l.id === logId);
  const log = logIndex === -1 ? undefined : logs[logIndex];
  const fingerprint = suppliedFingerprint || log?.approval?.actionFingerprint;
  if (!log || !fingerprint || log.status !== 'pending') return;
  if (log.approval && Date.parse(log.approval.expiresAt) <= Date.now()) {
    log.status = 'block';
    log.reason = 'Blocked: approval request expired';
    log.approval.userResponse = 'expired';
    db.addLog(log);
    pendingApprovalViews.delete(logId);
    syncStateToWebview();
    return;
  }
  {
    log.status = approved ? 'allow' : 'block';
    if (!approved) {
      log.reason = 'Blocked by user decision.';
    }
    if (log.approval) log.approval.userResponse = approved ? 'approve_once' : 'deny';
    db.addLog(log);
  }

  // Reply to proxy
  sendToProxy({
    type: 'approve_response',
    id: logId,
    actionFingerprint: fingerprint,
    approved
  });
  pendingApprovalViews.delete(logId);

  // Sync updated state to Webview
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
      proxyConnected: !!activeProxySocket,
      crossSurfaceRecords,
      traceIntegrity,
      pendingApprovals: Array.from(pendingApprovalViews.values())
        .filter(item => Date.parse(item.expiresAt) > Date.now())
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
          syncStateToWebview();
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
          db.clearLogs();
          syncStateToWebview();
          break;
      }
    });

    // Handle view state changes
    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) {
        syncStateToWebview();
      }
    });

    // Send initial sync
    setTimeout(syncStateToWebview, 500);
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
