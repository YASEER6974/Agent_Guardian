import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as readline from 'readline';
import { ChildProcess, spawn } from 'child_process';
import WebSocket from 'ws';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApprovalView, inferDestination, isTrustedDestination, resolveSessionPolicy } from './approval';
import { CrossSurfaceStore } from './browser/cross-surface-store';
import { GuardianDb } from './db';
import { readWorkspaceSettings } from './workspace-settings';
import { isHttpServer, resolveEnvironmentReferences, resolveHttpHeaders, validateServer } from './server-config';
import {
  autoAssignCategory,
  checkTransition
} from './detector';
import { DataLabel, Evidence, InspectionSummary } from './core/types';
import { scanSemanticSandboxed } from './semantic-sandbox';
import { AcceptedRiskStore } from './security/accepted-risks';
import {
  coarseTaint,
  createDataFlowState,
  matchInput,
  recordOutput,
  SessionDataFlowState
} from './security/data-flow';
import { inspectOnboarding, shadowingEvidence } from './security/onboarding';
import { inspectStructuredText } from './security/text-inspection';
import { diffToolDefinitions, fingerprintTool, snapshotTool } from './security/tool-integrity';
import {
  AuditLog,
  DownstreamServerConfig,
  ExtensionMessage,
  GuardianConfig,
  ProxyMessage,
  ResourceLimits
} from './types';
import type { SessionPolicy, ToolBaseline } from './types';

type JsonRpcId = string | number | null;

interface DownstreamRuntime {
  config: DownstreamServerConfig;
  signature: string;
  process?: ChildProcess;
  reader?: readline.Interface;
  http?: StreamableHTTPClientTransport;
  ready?: Promise<void>;
}

interface PendingDownstreamRequest {
  serverName: string;
  method: string;
  timer: NodeJS.Timeout;
  resolve: (message: any) => void;
  reject: (error: Error) => void;
}

interface PendingApproval {
  timer: NodeJS.Timeout;
  resolve: (approved: boolean) => void;
  log: AuditLog;
  actionFingerprint: string;
  expiresAt: number;
}

interface SessionState {
  categories: string[];
  lastCallTime: number;
  dataFlow: SessionDataFlowState;
  policy: SessionPolicy;
}

const DEFAULT_LIMITS: ResourceLimits = {
  maxMessageBytes: 1_048_576,
  maxNestingDepth: 64,
  requestTimeoutMs: Number(process.env.MCP_GUARDIAN_REQUEST_TIMEOUT_MS) || 10_000,
  approvalTimeoutMs: Number(process.env.MCP_GUARDIAN_APPROVAL_TIMEOUT_MS) || 120_000,
  maxScanStrings: 2_000,
  maxDiffEntries: 100
};
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const STORAGE_PATH = process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
const WS_DISABLED = process.env.MCP_GUARDIAN_WS_DISABLED === '1';
const WS_PORT = Number(process.env.MCP_GUARDIAN_WS_PORT) || 1337;
const WORKSPACE_SETTINGS_PATH = process.env.MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH;

const db = new GuardianDb(STORAGE_PATH);
if (WORKSPACE_SETTINGS_PATH) db.updateConfig(readWorkspaceSettings(WORKSPACE_SETTINGS_PATH, db.getConfig()));
const acceptedRisks = new AcceptedRiskStore(STORAGE_PATH);
const crossSurfaceStore = new CrossSurfaceStore(STORAGE_PATH);
const downstreams = new Map<string, DownstreamRuntime>();
const failedDownstreams = new Map<string, string>(); // serverName -> error message
const downstreamInitialization = new Map<string, Promise<void>>();
const pendingDownstream = new Map<string, PendingDownstreamRequest>();
const pendingApprovals = new Map<string, PendingApproval>();
const sessions = new Map<string, SessionState>();
const toolsMapping = new Map<string, { serverName: string; originalName: string }>();
const toolOwners = new Map<string, Set<string>>();

let requestSequence = 0;
let ws: WebSocket | null = null;
let wsConnected = false;
let wsReconnectTimer: NodeJS.Timeout | undefined;
let startupSyncTimer: NodeJS.Timeout | undefined;
let shuttingDown = false;
let clientInitializeParams: unknown;
let clientHasInitialized = false;
let resolveStartupConfig: (() => void) | undefined;
const startupConfigReady = new Promise<void>(resolve => { resolveStartupConfig = resolve; });

const clientReader = readline.createInterface({ input: process.stdin, terminal: false });

function limits(): ResourceLimits {
  return { ...DEFAULT_LIMITS, ...(db.getConfig().resourceLimits || {}) };
}

function nextRequestId(): string {
  requestSequence += 1;
  return `guardian-${process.pid}-${requestSequence}-${crypto.randomBytes(6).toString('hex')}`;
}

function writeToClient(message: any): void {
  const serialized = JSON.stringify(message);
  if (Buffer.byteLength(serialized, 'utf8') > limits().maxMessageBytes) {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: message?.id ?? null,
      error: { code: -32002, message: 'Guardian response exceeded configured size limit' }
    }) + '\n');
    return;
  }
  process.stdout.write(serialized + '\n');
}

function writeError(id: JsonRpcId, code: number, message: string, data?: unknown): void {
  writeToClient({ jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } });
}

function validateIncomingLine(line: string): any {
  if (Buffer.byteLength(line, 'utf8') > limits().maxMessageBytes) {
    throw new Error('Message exceeded configured size limit');
  }
  const parsed = JSON.parse(line);
  if (exceedsDepth(parsed, limits().maxNestingDepth)) {
    throw new Error('Message exceeded configured nesting-depth limit');
  }
  return parsed;
}

function exceedsDepth(value: unknown, maximum: number): boolean {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (current.depth > maximum) return true;
    if (current.value === null || typeof current.value !== 'object') continue;
    const children = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value as Record<string, unknown>);
    for (const child of children) pending.push({ value: child, depth: current.depth + 1 });
  }
  return false;
}

function resolveCommand(command: string): string {
  if (process.platform !== 'win32' || path.extname(command)) return command;
  const lower = command.toLowerCase();
  return lower === 'npm' || lower === 'npx' || lower === 'pnpm' || lower === 'yarn'
    ? `${command}.cmd`
    : command;
}

function serverSignature(config: DownstreamServerConfig): string {
  return JSON.stringify(config);
}

function connectToExtension(): void {
  if (WS_DISABLED || shuttingDown || ws) return;
  const socket = new WebSocket(`ws://127.0.0.1:${WS_PORT}`);
  ws = socket;

  socket.on('open', () => {
    if (ws !== socket) return;
    wsConnected = true;
    console.error(`[MCP-Guardian-Proxy] Connected to VS Code extension on port ${WS_PORT}`);
    // Wait for update_config; a connected socket alone does not mean the
    // extension has supplied its workspace settings yet.
    sendToExtension({
      type: 'sync_state',
      baselines: db.getBaselines(),
      logs: db.getLogs(),
      config: db.getConfig()
    });
  });

  socket.on('message', data => {
    try {
      handleExtensionMessage(validateIncomingLine(data.toString()) as ExtensionMessage);
    } catch (error) {
      console.error('[MCP-Guardian-Proxy] Invalid extension message:', error);
    }
  });

  const disconnected = () => {
    if (ws !== socket) return;
    wsConnected = false;
    ws = null;
    if (!shuttingDown) wsReconnectTimer = setTimeout(connectToExtension, 3_000);
  };
  socket.on('close', disconnected);
  socket.on('error', disconnected);
}

function sendToExtension(message: ProxyMessage): void {
  if (!ws || !wsConnected || ws.readyState !== WebSocket.OPEN) return;
  const serialized = JSON.stringify(message);
  // Aggregated dashboard state contains both trusted and observed definitions
  // for hundreds of tools. Its local IPC budget is separate from the external
  // MCP message limit; do not silently drop a real provider's dashboard snapshot.
  const budget = message.type === 'sync_state' ? 16_777_216 : limits().maxMessageBytes;
  if (Buffer.byteLength(serialized, 'utf8') <= budget) ws.send(serialized);
  else console.error(`[MCP-Guardian-Proxy] Dashboard ${message.type} exceeds its bounded IPC budget (${budget} bytes)`);
}

function handleExtensionMessage(message: ExtensionMessage): void {
  switch (message.type) {
    case 'approve_response': {
      const pending = pendingApprovals.get(message.id);
      if (!pending) return;
      if (Date.now() >= pending.expiresAt || message.actionFingerprint !== pending.actionFingerprint) {
        clearTimeout(pending.timer);
        pendingApprovals.delete(message.id);
        pending.log.status = 'block';
        pending.log.reason = Date.now() >= pending.expiresAt
          ? 'Blocked: approval response arrived after expiry'
          : 'Blocked: approval response did not match the exact action';
        if (pending.log.approval) pending.log.approval.userResponse = Date.now() >= pending.expiresAt ? 'expired' : 'invalid';
        persistLog(pending.log);
        pending.resolve(false);
        return;
      }
      clearTimeout(pending.timer);
      pendingApprovals.delete(message.id);
      if (pending.log.approval) pending.log.approval.userResponse = message.approved ? 'approve_once' : 'deny';
      pending.resolve(message.approved);
      return;
    }
    case 'approve_drift':
      db.approveDrift(message.serverName, message.toolName, message.newHash);
      sendState();
      return;
    case 'set_category':
      db.setToolCategory(message.serverName, message.toolName, message.category);
      sendState();
      return;
    case 'update_config':
      // Cancel the fallback startup timer — we have the authoritative workspace config now.
      if (startupSyncTimer !== undefined) {
        clearTimeout(startupSyncTimer);
        startupSyncTimer = undefined;
      }
      // An explicitly supplied workspace file takes precedence over a stale
      // extension instance or a different VS Code window sharing this port.
      db.updateConfig({ ...message.config,
        ...(WORKSPACE_SETTINGS_PATH ? readWorkspaceSettings(WORKSPACE_SETTINGS_PATH, db.getConfig()) : {}) });
      syncDownstreamServers();
      return;
    case 'request_state':
      db.refresh();
      sendState();
      return;
    case 'clear_logs':
      db.clearLogs();
      sendState();
  }
}

function sendState(): void {
  sendToExtension({
    type: 'sync_state',
    baselines: db.getBaselines(),
    logs: db.getLogs(),
    config: db.getConfig()
  });
}

function syncDownstreamServers(): void {
  const configured = db.getConfig().servers || [];
  const seen = new Set<string>();
  let changed = false;

  for (const server of configured) {
    if (!server.name || seen.has(server.name)) {
      console.error(`[MCP-Guardian-Proxy] Ignoring invalid or duplicate server name '${server.name}'`);
      continue;
    }
    seen.add(server.name);
    failedDownstreams.delete(server.name); // clear any previous failure so we retry
    const current = downstreams.get(server.name);
    const signature = serverSignature(server);
    if (current && current.signature === signature) continue;
    changed = true;
    if (current) stopDownstreamServer(server.name, 'configuration changed');
    startDownstreamServer(server);
  }

  for (const name of downstreams.keys()) {
    if (!seen.has(name)) { changed = true; stopDownstreamServer(name, 'removed from configuration'); }
  }
  for (const name of failedDownstreams.keys()) {
    if (!seen.has(name)) failedDownstreams.delete(name);
  }
  resolveStartupConfig?.();
  resolveStartupConfig = undefined;
  if (changed && clientHasInitialized) {
    void Promise.allSettled(Array.from(downstreamInitialization.values())).then(() => {
      if (!shuttingDown) writeToClient({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
    });
  }
}

function startDownstreamServer(config: DownstreamServerConfig): void {
  try {
    validateServer(config);
    if (isHttpServer(config)) { startHttpServer(config); return; }
  } catch (error) {
    failedDownstreams.set(config.name, error instanceof Error ? error.message : 'Invalid server configuration');
    return;
  }
  let child: ChildProcess;
  try {
    const args = (config.args || []).map(resolveEnvironmentReferences);
    const command = resolveCommand(resolveEnvironmentReferences(config.command!));
    console.error(`[MCP-Guardian-Proxy] Starting downstream server '${config.name}' via ${command}`);
    child = spawn(command, args, {
      env: { ...process.env, ...Object.fromEntries(Object.entries(config.env || {}).map(([key, value]) => [key, resolveEnvironmentReferences(value)])) },
      cwd: config.cwd,
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: false,
      windowsHide: true
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message : 'Failed to start server';
    console.error(`[MCP-Guardian-Proxy] Server '${config.name}' failed to spawn:`, msg);
    failedDownstreams.set(config.name, msg);
    sendToExtension({
      type: 'downstream_status',
      serverName: config.name,
      status: 'error',
      error: msg
    });
    return;
  }

  if (!child.stdout || !child.stdin) {
    child.kill();
    const msg = `Downstream server '${config.name}' did not expose piped stdio`;
    failedDownstreams.set(config.name, msg);
    throw new Error(msg);
  }

  const reader = readline.createInterface({ input: child.stdout, terminal: false });
  const runtime: DownstreamRuntime = { config, signature: serverSignature(config), process: child, reader };
  downstreams.set(config.name, runtime);
  if (clientHasInitialized) {
    void initializeDownstream(config.name).catch(error => {
      console.error(`[MCP-Guardian-Proxy] Downstream initialize failed for '${config.name}':`, error.message);
      failedDownstreams.set(config.name, error.message);
    });
  }

  reader.on('line', line => handleDownstreamLine(config.name, line));
  child.once('spawn', () => {
    sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'connected' });
  });
  child.once('error', error => {
    console.error(`[MCP-Guardian-Proxy] Server '${config.name}' error:`, error.message);
    failedDownstreams.set(config.name, error.message);
    sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'error', error: error.message });
    failPendingForServer(config.name, new Error(`Server '${config.name}' failed: ${error.message}`));
  });
  child.once('close', code => {
    const isCurrent = downstreams.get(config.name)?.process === child;
    if (isCurrent) {
      downstreams.delete(config.name);
      downstreamInitialization.delete(config.name);
      const reason = `Server '${config.name}' exited with code ${code}`;
      console.error(`[MCP-Guardian-Proxy] ${reason}`);
      if (!shuttingDown && !failedDownstreams.has(config.name)) failedDownstreams.set(config.name, reason);
    }
    reader.close();
    if (isCurrent) {
      failPendingForServer(config.name, new Error(`Server '${config.name}' exited with code ${code}`));
      sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'disconnected' });
    }
  });
}

function startHttpServer(config: DownstreamServerConfig): void {
  const transport = new StreamableHTTPClientTransport(new URL(config.url!), {
    requestInit: { headers: resolveHttpHeaders(config), redirect: 'error' },
    fetch: async (url, options) => {
      const signals = [options?.signal, options?.method === 'GET' ? undefined : AbortSignal.timeout(limits().requestTimeoutMs)]
        .filter((signal): signal is AbortSignal => !!signal);
      const response = await fetch(url, { ...options, redirect: 'error', signal: signals.length ? AbortSignal.any(signals) : undefined });
      if (!response.body || options?.method === 'GET') return response;
      const reader = response.body.getReader();
      let bytes = 0;
      const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            const chunk = await reader.read();
            if (chunk.done) { controller.close(); return; }
            bytes += chunk.value.byteLength;
            if (bytes > limits().maxMessageBytes) {
              await reader.cancel();
              controller.error(new Error('HTTP MCP response exceeded the size limit'));
              return;
            }
            controller.enqueue(chunk.value);
          } catch (error) { controller.error(error); }
        },
        cancel: reason => reader.cancel(reason)
      });
      return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
    }
  });
  const runtime: DownstreamRuntime = { config, signature: serverSignature(config), http: transport };
  downstreams.set(config.name, runtime);
  console.error(`[MCP-Guardian-Proxy] Connecting HTTP MCP server '${config.name}'`);
  transport.onmessage = message => {
    if (downstreams.get(config.name) === runtime) handleDownstreamLine(config.name, JSON.stringify(message));
  };
  transport.onerror = () => sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'error', error: 'HTTP MCP connection failed; inspect the client error' });
  transport.onclose = () => {
    if (downstreams.get(config.name) !== runtime) return;
    downstreams.delete(config.name);
    downstreamInitialization.delete(config.name);
    failedDownstreams.set(config.name, 'HTTP MCP connection closed');
    failPendingForServer(config.name, new Error('HTTP MCP connection closed'));
    sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'disconnected' });
  };
  runtime.ready = transport.start();
  if (clientHasInitialized) void initializeDownstream(config.name).catch(error => failedDownstreams.set(config.name, error.message));
}

async function sendDownstream(runtime: DownstreamRuntime, message: any): Promise<void> {
  if (runtime.http) { await runtime.ready; await runtime.http.send(message); return; }
  if (!runtime.process?.stdin?.writable) throw new Error(`Server '${runtime.config.name}' is not running`);
  await new Promise<void>((resolve, reject) => runtime.process!.stdin!.write(JSON.stringify(message) + '\n', error => error ? reject(error) : resolve()));
}

function stopDownstreamServer(name: string, reason: string): void {
  const runtime = downstreams.get(name);
  if (!runtime) return;
  downstreams.delete(name);
  downstreamInitialization.delete(name);
  runtime.reader?.close();
  runtime.process?.kill();
  if (runtime.http) void runtime.http.close();
  failPendingForServer(name, new Error(`Server '${name}' stopped: ${reason}`));
}

function failPendingForServer(serverName: string, error: Error): void {
  for (const [id, pending] of pendingDownstream.entries()) {
    if (pending.serverName !== serverName) continue;
    clearTimeout(pending.timer);
    pendingDownstream.delete(id);
    pending.reject(error);
  }
}

function handleDownstreamLine(serverName: string, line: string): void {
  let message: any;
  try {
    message = validateIncomingLine(line);
  } catch (error) {
    console.error(`[MCP-Guardian-Proxy] Rejected invalid output from '${serverName}':`, error);
    failPendingForServer(serverName, error instanceof Error ? error : new Error('Invalid downstream output'));
    return;
  }

  if (typeof message.id === 'string' && pendingDownstream.has(message.id)) {
    const pending = pendingDownstream.get(message.id)!;
    if (pending.serverName !== serverName) {
      console.error(`[MCP-Guardian-Proxy] Ignored response-id collision from '${serverName}'`);
      return;
    }
    clearTimeout(pending.timer);
    pendingDownstream.delete(message.id);
    if (message.error) {
      const inspected = inspectStructuredText(message.error, 'mcp.error-response', `error:${message.id}`, limits().maxScanStrings);
      if (inspected.truncated || inspected.evidence.some(item => ['high', 'critical'].includes(item.severity))) {
        message.error = { code: -32603, message: 'External MCP error content blocked by Agent Guardian' };
      }
    }
    pending.resolve(message);
    return;
  }

  if (message.id === undefined) writeToClient(message);
  else console.error(`[MCP-Guardian-Proxy] Ignored unknown response id from '${serverName}'`);
}

function requestDownstream(serverName: string, method: string, params: unknown): Promise<any> {
  const runtime = downstreams.get(serverName);
  if (!runtime) {
    return Promise.reject(new Error(`Server '${serverName}' is not running`));
  }
  const id = nextRequestId();
  const request = { jsonrpc: '2.0', id, method, params };
  const serialized = JSON.stringify(request);
  if (Buffer.byteLength(serialized, 'utf8') > limits().maxMessageBytes) {
    return Promise.reject(new Error('Downstream request exceeded configured size limit'));
  }

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingDownstream.delete(id);
      reject(new Error(`Server '${serverName}' timed out handling '${method}'`));
    }, limits().requestTimeoutMs);
    pendingDownstream.set(id, { serverName, method, timer, resolve, reject });
    void sendDownstream(runtime, request).catch(error => {
      clearTimeout(timer);
      pendingDownstream.delete(id);
      reject(runtime.http ? new Error(`HTTP MCP '${serverName}' request '${method}' failed${typeof error.code === 'number' ? ` (HTTP ${error.code})` : ''}; check the endpoint and authentication configuration`) : error);
    });
  });
}

function initializeDownstream(serverName: string): Promise<void> {
  const existing = downstreamInitialization.get(serverName);
  if (existing) return existing;
  const initialized = requestDownstream(serverName, 'initialize', clientInitializeParams || {}).then(response => {
    if (response.error) throw new Error(`Server '${serverName}' rejected initialize: ${response.error.message}`);
    const runtime = downstreams.get(serverName);
    if (response.result?.protocolVersion) runtime?.http?.setProtocolVersion(response.result.protocolVersion);
    sendToExtension({ type: 'downstream_status', serverName, status: 'connected' });
    if (clientHasInitialized) {
      if (runtime) void sendDownstream(runtime, { jsonrpc: '2.0', method: 'notifications/initialized' }).catch(() => {});
    }
  });
  downstreamInitialization.set(serverName, initialized);
  return initialized;
}

function notifyDownstreams(method: string, params?: unknown): void {
  const message = { jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) };
  for (const runtime of downstreams.values()) void sendDownstream(runtime, message).catch(error => {
    console.error(`[MCP-Guardian-Proxy] Notification to '${runtime.config.name}' failed: ${error.message}`);
  });
}

clientReader.on('line', line => {
  if (!line.trim()) return;
  let message: any;
  try {
    message = validateIncomingLine(line);
  } catch (error) {
    writeError(null, -32700, error instanceof Error ? error.message : 'Invalid JSON');
    return;
  }
  void handleClientRequest(message).catch(error => {
    console.error('[MCP-Guardian-Proxy] Request failed:', error);
    writeError(message.id ?? null, -32603, error instanceof Error ? error.message : 'Internal Guardian error');
  });
});

clientReader.on('close', () => void shutdown('stdin closed'));
process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

async function handleClientRequest(message: any): Promise<void> {
  if (message?.jsonrpc !== '2.0') {
    writeError(message?.id ?? null, -32600, 'Invalid JSON-RPC version');
    return;
  }
  if (typeof message.method !== 'string') {
    writeError(message.id ?? null, -32600, 'JSON-RPC method must be a string');
    return;
  }

  if (message.method === 'initialize') {
    clientInitializeParams = message.params || {};
    await startupConfigReady;
    const names = Array.from(downstreams.keys());
    if (failedDownstreams.size > 0 || names.length === 0) {
      writeError(message.id ?? null, -32001, 'No healthy downstream MCP servers available', {
        failures: Array.from(failedDownstreams.entries()).map(([name, error]) => `${name}: ${error}`)
      });
      return;
    }
    const initialized = await Promise.allSettled(names.map(initializeDownstream));
    const failures = initialized.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
      .map(result => result.reason instanceof Error ? result.reason.message : String(result.reason));
    if (failures.length > 0) {
      writeError(message.id ?? null, -32001, 'Downstream initialization failed', { failures });
      return;
    }
    writeToClient({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {}, resources: {} },
        serverInfo: { name: 'mcp-guardian-proxy', version: '1.1.0' }
      }
    });
    return;
  }

  if (message.method === 'notifications/initialized') {
    clientHasInitialized = true;
    notifyDownstreams('notifications/initialized', message.params);
    return;
  }

  if (message.id === undefined) {
    notifyDownstreams(message.method, message.params);
    return;
  }

  if (message.method === 'tools/list') {
    await handleToolsList(message);
    return;
  }

  if (message.method === 'tools/call') {
    await handleToolCall(message);
    return;
  }

  const firstServer = downstreams.keys().next().value as string | undefined;
  if (!firstServer) {
    writeError(message.id ?? null, -32000, 'No downstream MCP servers available');
    return;
  }
  try {
    const response = await requestDownstream(firstServer, message.method, message.params || {});
    if (!response.error && (message.method.startsWith('resources/') || message.method.startsWith('prompts/'))) {
      const eventId = `${message.method}:${crypto.randomUUID()}`;
      const inspection = inspectStructuredText(
        response.result,
        `mcp.${message.method.replace('/', '.')}`,
        eventId,
        limits().maxScanStrings
      );
      const evidence = inspection.evidence.filter(finding => !acceptedRisks.isAccepted(finding));
      if (inspection.truncated || evidence.some(finding => finding.severity === 'high' || finding.severity === 'critical')) {
        writeError(message.id ?? null, -32603, 'MCP content blocked by Agent Guardian', {
          method: message.method,
          incomplete: inspection.truncated,
          evidence: evidence.map(finding => ({ id: finding.id, message: finding.message, severity: finding.severity }))
        });
        return;
      }
    }
    writeToClient({ jsonrpc: '2.0', id: message.id, ...(response.error ? { error: response.error } : { result: response.result }) });
  } catch (error) {
    writeError(message.id ?? null, -32001, error instanceof Error ? error.message : 'Downstream request failed');
  }
}

async function handleToolsList(message: any): Promise<void> {
  await startupConfigReady;
  const initialized = await Promise.allSettled(Array.from(downstreamInitialization.values()));
  const initializationFailures = initialized.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
    .map(result => result.reason instanceof Error ? result.reason.message : String(result.reason));
  const serverNames = Array.from(downstreams.keys());
  // Report any servers that were configured but failed to start.
  const startupFailures = Array.from(failedDownstreams.entries()).map(
    ([name, err]) => `Server '${name}' failed to start: ${err}`
  );
  if (serverNames.length === 0 || startupFailures.length > 0 || initializationFailures.length > 0) {
    writeError(message.id ?? null, -32001, 'Tool discovery was incomplete', {
      failures: [...startupFailures, ...initializationFailures, ...(serverNames.length === 0 ? ['No downstream MCP servers are running'] : [])]
    });
    return;
  }

  const results = await Promise.allSettled(
    serverNames.map(async serverName => ({
      serverName,
      response: await listDownstreamTools(serverName, message.params || {})
    }))
  );
  const failures = results
    .filter((result): result is PromiseRejectedResult => result.status === 'rejected')
    .map(result => result.reason instanceof Error ? result.reason.message : String(result.reason));
  if (failures.length > 0) {
    writeError(message.id ?? null, -32001, 'Tool discovery was incomplete', { failures });
    return;
  }

  const aggregatedTools: any[] = [];
  toolOwners.clear();
  for (const result of results as PromiseFulfilledResult<{ serverName: string; response: any }>[]) {
    if (result.value.response.error) {
      writeError(message.id ?? null, -32001, `Server '${result.value.serverName}' rejected tools/list`, result.value.response.error);
      return;
    }
    registerTools(result.value.serverName, result.value.response.result?.tools || [], aggregatedTools);
  }
  applyShadowingRules();
  sendState();
  writeToClient({ jsonrpc: '2.0', id: message.id, result: { tools: aggregatedTools } });
}

async function listDownstreamTools(serverName: string, params: any = {}): Promise<any> {
  const tools: any[] = [];
  const cursors = new Set<string>();
  let cursor = params.cursor;
  for (let page = 0; page < 40; page++) {
    const response = await requestDownstream(serverName, 'tools/list', { ...params, ...(cursor ? { cursor } : {}) });
    if (response.error) return response;
    if (!Array.isArray(response.result?.tools)) throw new Error(`Server '${serverName}' returned an invalid tools list`);
    tools.push(...response.result.tools);
    if (Buffer.byteLength(JSON.stringify(tools)) > limits().maxMessageBytes) throw new Error('Aggregated tool definitions exceeded the size limit');
    cursor = response.result.nextCursor;
    if (!cursor) return { result: { tools } };
    if (typeof cursor !== 'string' || cursors.has(cursor)) throw new Error('Invalid or repeated tool-list pagination cursor');
    cursors.add(cursor);
  }
  throw new Error('Tool-list pagination limit reached; discovery is incomplete');
}

function registerTools(serverName: string, tools: any[], output: any[]): void {
  const serverConfig = downstreams.get(serverName)?.config;
  if (!serverConfig) return;
  const discoveredBaselines: Record<string, ToolBaseline> = {};
  const discoveryLogs: AuditLog[] = [];
  for (const tool of tools) {
    const prefixedName = `${serverName}__${tool.name}`;
    toolsMapping.set(prefixedName, { serverName, originalName: tool.name });
    if (!toolOwners.has(tool.name)) toolOwners.set(tool.name, new Set());
    toolOwners.get(tool.name)!.add(serverName);
    const eventId = `discovery:${serverName}:${tool.name}:${crypto.randomUUID()}`;
    const observedDefinition = snapshotTool(tool);
    const currentHash = fingerprintTool(observedDefinition);
    const baseline = db.getToolBaseline(serverName, tool.name);
    const onboarding = inspectOnboarding(
      serverConfig,
      observedDefinition,
      eventId,
      acceptedRisks,
      limits().maxScanStrings
    );
    let statusText = 'SAFE';
    let isDrift = false;
    const reasons: string[] = [];

    if (!baseline) {
      const now = new Date().toISOString();
      const assignedCategory = autoAssignCategory(tool.name, tool.description);
      const firstSeenPolicy = db.getConfig().firstSeenPolicy || 'approve-safe';
      const approved = onboarding.safe && firstSeenPolicy === 'approve-safe';
      const status = !onboarding.safe || firstSeenPolicy === 'block'
        ? 'rejected'
        : approved
          ? 'approved'
          : 'pending';
      discoveredBaselines[tool.name] = {
        name: tool.name,
        description: tool.description || '',
        inputSchema: tool.inputSchema || {},
        hash: currentHash,
        category: isHttpServer(serverConfig) && assignedCategory === 'READ_LOCAL' ? 'READ_NETWORK' : assignedCategory,
        approved,
        firstSeen: now,
        lastSeen: now,
        status,
        trustedDefinition: observedDefinition,
        observedDefinition,
        observedHash: currentHash,
        differences: [],
        inspection: onboarding.inspection,
        evidence: onboarding.evidence
      };
      if (!approved) {
        statusText = status === 'rejected' ? 'REJECTED' : 'PENDING';
        reasons.push(status === 'rejected'
          ? 'Onboarding scan rejected the first-seen tool definition'
          : 'First-seen tool requires explicit approval');
      }
    } else {
      const trustedDefinition = baseline.trustedDefinition || snapshotTool(baseline);
      if (baseline.hash !== currentHash) {
        isDrift = true;
        statusText = 'DRIFT';
        reasons.push('Metadata hash changed from the approved baseline');
        const diff = diffToolDefinitions(trustedDefinition, observedDefinition, limits().maxDiffEntries);
        baseline.approved = false;
        baseline.status = 'drifted';
        baseline.differences = diff.differences;
        if (diff.truncated) reasons.push('Schema diff was truncated at the configured limit');
      } else if (!onboarding.safe) {
        baseline.approved = false;
        baseline.status = 'rejected';
        statusText = 'REJECTED';
        reasons.push('Security scan rejected the observed tool definition');
      }
      baseline.trustedDefinition = trustedDefinition;
      baseline.observedDefinition = observedDefinition;
      baseline.observedHash = currentHash;
      baseline.inspection = onboarding.inspection;
      baseline.evidence = onboarding.evidence;
      baseline.lastSeen = new Date().toISOString();
      discoveredBaselines[tool.name] = baseline;
    }

    for (const finding of onboarding.evidence) reasons.push(finding.message);

    // Never expose a rejected or changed definition to the agent's context.
    if (onboarding.safe && !isDrift && !['rejected', 'drifted'].includes(discoveredBaselines[tool.name]?.status || '')) {
      output.push({ ...tool, name: prefixedName, description: `[MCP-Guardian: ${statusText}] ${tool.description || ''}` });
    }
    const stored = discoveredBaselines[tool.name];
    if (isDrift || onboarding.evidence.length > 0 || !stored?.approved) {
      const auditLog: AuditLog = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        serverName,
        toolName: tool.name,
        category: baseline?.category || 'GENERAL',
        arguments: {},
        status: 'block',
        reason: uniqueReasons(reasons).join('; '),
        drift: isDrift || undefined,
        promptInjection: onboarding.evidence.length > 0 || undefined,
        evidence: onboarding.evidence,
        inspection: onboarding.inspection
      };
      discoveryLogs.push(auditLog);
    }
  }
  db.applyDiscovery(serverName, discoveredBaselines, discoveryLogs);
  for (const log of discoveryLogs) sendToExtension({ type: 'log', log });
}

function applyShadowingRules(): void {
  for (const [toolName, owners] of toolOwners.entries()) {
    if (owners.size < 2) continue;
    const serverNames = Array.from(owners);
    const finding = shadowingEvidence(toolName, serverNames, `shadow:${toolName}`);
    if (acceptedRisks.isAccepted(finding)) continue;
    for (const serverName of serverNames) {
      const baseline = db.getToolBaseline(serverName, toolName);
      if (!baseline) continue;
      baseline.approved = false;
      baseline.status = 'pending';
      baseline.evidence = deduplicateEvidence([...(baseline.evidence || []), finding]);
      db.setToolBaseline(serverName, toolName, baseline);
      persistLog({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        serverName,
        toolName,
        category: baseline.category,
        arguments: {},
        status: 'block',
        reason: finding.message,
        evidence: [finding]
      });
    }
  }
}

async function handleToolCall(message: any): Promise<void> {
  const prefixedName = message.params?.name;
  if (typeof prefixedName !== 'string') {
    writeError(message.id ?? null, -32602, 'tools/call requires a tool name');
    return;
  }
  const mapping = toolsMapping.get(prefixedName);
  if (!mapping) {
    writeError(message.id ?? null, -32601, `Tool '${prefixedName}' was not discovered`);
    return;
  }

  // Recheck every transport, including stdio bridges to hosted MCPs. A local
  // launcher does not mean its tool definitions cannot change remotely.
  {
    try {
      const refreshed = await listDownstreamTools(mapping.serverName);
      if (refreshed.error) throw new Error('MCP server rejected metadata refresh');
      registerTools(mapping.serverName, refreshed.result.tools, []);
      applyShadowingRules();
      sendState();
      if (!refreshed.result.tools.some((tool: any) => tool.name === mapping.originalName)) {
        throw new Error('Tool disappeared; restart discovery before calling it');
      }
    } catch (error) {
      writeError(message.id ?? null, -32603, `Tool metadata could not be verified: ${error instanceof Error ? error.message : 'refresh failed'}`);
      return;
    }
  }

  const args = message.params?.arguments || {};
  const sessionContext = resolveSessionPolicy(message.params?._meta, db.getConfig().sessionPolicy);
  const sessionId = sessionContext.sessionId;
  const session = sessionState(sessionId, sessionContext.policy);
  session.policy = sessionContext.policy;
  const baseline = db.getToolBaseline(mapping.serverName, mapping.originalName);
  const category = baseline?.category || 'GENERAL';
  const destination = inferDestination(args);
  const callEventId = `call:${sessionId}:${crypto.randomUUID()}`;
  const reasons: string[] = [];
  const evidence: Evidence[] = [];
  let isDrift = false;
  let isInjection = false;
  let isViolation = false;
  let hardBlock = false;

  if (!baseline) {
    hardBlock = true;
    reasons.push('Tool has no onboarding baseline');
    evidence.push(makeEvidence('mcp.integrity', 'R2', 'critical', 'Tool has no onboarding baseline', callEventId));
  } else if (!baseline.approved) {
    const status = baseline.status || 'pending';
    isDrift = status === 'drifted';
    hardBlock = status === 'drifted' || status === 'rejected';
    const reason = status === 'drifted'
      ? 'Tool definition drifted and must be explicitly re-baselined'
      : status === 'rejected'
        ? 'Tool definition failed onboarding security checks'
        : 'Tool is unknown or shadowed and requires explicit approval';
    reasons.push(reason);
    evidence.push(...(baseline.evidence || []));
    evidence.push(makeEvidence('mcp.integrity', status === 'drifted' ? 'R1' : 'R2', hardBlock ? 'critical' : 'high', reason, callEventId, {
      status,
      observedHash: baseline.observedHash,
      trustedHash: baseline.hash
    }));
  }
  const argumentInspection = inspectStructuredText(
    args,
    'mcp.arguments',
    callEventId,
    limits().maxScanStrings
  );
  const argumentEvidence = argumentInspection.evidence.filter(finding => !acceptedRisks.isAccepted(finding));
  if (argumentEvidence.length > 0) {
    isInjection = true;
    evidence.push(...argumentEvidence);
    reasons.push(...argumentEvidence.map(finding => finding.message));
  }
  if (argumentInspection.truncated) {
    hardBlock = true;
    reasons.push('Argument inspection was incomplete because the string limit was reached');
  }
  const previousCategory = session.categories.at(-1);
  if (checkTransition(previousCategory, category, db.getConfig().forbiddenTransitions)) {
    isViolation = true;
    const reason = `Forbidden transition: ${previousCategory} -> ${category}`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.behavior', undefined, 'high', reason, callEventId));
  }

  if (session.policy.allowedCapabilities.length > 0 && !session.policy.allowedCapabilities.includes(category)) {
    const reason = `Capability ${category} is outside the declared session policy`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.session-policy', 'R3', 'high', reason, callEventId, {
      allowedCapabilities: session.policy.allowedCapabilities
    }));
  }
  if (destination && session.policy.trustedDestinations.length > 0 &&
    !isTrustedDestination(destination, session.policy.trustedDestinations)) {
    const reason = `Destination '${destination}' is not trusted by the session policy`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.session-policy', 'R4', 'high', reason, callEventId, { destination }));
  }

  const flowMatch = matchInput(session.dataFlow, args);
  const outbound = category === 'WRITE_COMMUNICATION' || category === 'EXECUTE_SYSTEM';
  const coarseLabels = outbound ? coarseTaint(session.dataFlow) : [];
  const flowLabels = new Set<DataLabel>([...flowMatch.labels, ...coarseLabels]);
  if (outbound && flowLabels.has('credential')) {
    hardBlock = true;
    const reason = `Credential-labelled session data is flowing to ${category}`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.data-flow', 'R5', 'critical', reason, callEventId, {
      dataLabel: 'credential',
      match: flowMatch.exact ? 'exact-fingerprint' : 'coarse-session-taint'
    }));
  } else if (outbound && (flowLabels.has('sensitive') || flowLabels.has('personal') || flowLabels.has('financial'))) {
    const reason = `Sensitive session data may be flowing to ${category}`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.data-flow', 'R4', 'high', reason, callEventId, {
      dataLabel: flowLabels.has('financial') ? 'financial' : flowLabels.has('personal') ? 'personal' : 'sensitive',
      match: flowMatch.exact ? 'exact-fingerprint' : 'coarse-session-taint'
    }));
  }
  const browserInfluence = crossSurfaceStore.matchBrowserInfluence(sessionId, args);
  for (const label of browserInfluence.labels) flowLabels.add(label);
  const browserUntrusted = browserInfluence.influenced && browserInfluence.labels.includes('untrusted');
  const privilegedMcp = ['WRITE_LOCAL', 'WRITE_COMMUNICATION', 'EXECUTE_SYSTEM'].includes(category);
  if (browserUntrusted && privilegedMcp) {
    const ruleId = category === 'EXECUTE_SYSTEM' ? 'R7' : 'R8';
    const reason = category === 'EXECUTE_SYSTEM'
      ? 'Untrusted browser content influenced a system-execution MCP action'
      : `Untrusted browser content influenced an MCP ${category} action`;
    if (ruleId === 'R7') hardBlock = true;
    reasons.push(reason);
    evidence.push(makeEvidence('cross-surface.browser-to-mcp', ruleId, ruleId === 'R7' ? 'critical' : 'high', reason, callEventId, {
      match: browserInfluence.exact ? 'exact-fingerprint' : 'coarse-session-taint',
      sourceEventIds: browserInfluence.sourceEventIds
    }));
  }
  session.categories.push(category);
  session.lastCallTime = Date.now();

  if (evidence.some(finding => finding.ruleId === 'R9') && reasons.length > 1) hardBlock = true;

  const inspection: InspectionSummary = inspectionSummary(
    argumentInspection.stringsInspected,
    argumentInspection.truncated,
    argumentInspection.truncated ? 'Argument string limit reached' : undefined
  );

  const auditLog: AuditLog = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    serverName: mapping.serverName,
    toolName: mapping.originalName,
    category,
    arguments: args,
    status: reasons.length > 0 ? 'pending' : 'allow',
    reason: uniqueReasons(reasons).join('; ') || undefined,
    drift: isDrift || undefined,
    promptInjection: isInjection || undefined,
    isCategoryTransitionViolation: isViolation || undefined,
    sessionId,
    evidence: deduplicateEvidence(evidence),
    dataLabels: Array.from(flowLabels),
    inspection,
    intent: session.policy.intent || undefined,
    destination
  };

  if (!hardBlock && db.getConfig().geminiApiKey && baseline) {
    const semantic = await scanSemanticSandboxed(
      mapping.originalName,
      JSON.stringify({ definition: baseline.observedDefinition || baseline.trustedDefinition, arguments: args }),
      db.getConfig().geminiApiKey!,
      Math.min(limits().requestTimeoutMs, 4_000)
    );
    if (semantic.suspicious) {
      isInjection = true;
      reasons.push(`Semantic scan flagged description: ${semantic.reason}`);
      evidence.push(makeEvidence('mcp.semantic-sandbox', undefined, 'high', semantic.reason || 'Semantic scan flagged content', callEventId));
    } else if (!semantic.complete) {
      reasons.push(semantic.reason || 'Semantic inspection was incomplete');
    }
    auditLog.status = reasons.length > 0 ? 'pending' : 'allow';
    auditLog.reason = uniqueReasons(reasons).join('; ') || undefined;
    auditLog.evidence = deduplicateEvidence(evidence);
    auditLog.promptInjection = isInjection || undefined;
    auditLog.inspection = {
      ...inspection,
      complete: inspection.complete && semantic.complete,
      partial: inspection.partial + (semantic.complete ? 0 : 1),
      total: inspection.total + 1,
      completed: inspection.completed + (semantic.complete ? 1 : 0),
      reasons: semantic.complete ? inspection.reasons : [...inspection.reasons, semantic.reason || 'Semantic inspection incomplete']
    };
  }

  if (hardBlock) {
    auditLog.status = 'block';
    auditLog.reason = uniqueReasons(reasons).join('; ');
    auditLog.evidence = deduplicateEvidence(evidence);
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, auditLog.reason || 'Execution blocked by Guardian policy');
    return;
  }

  if (reasons.length === 0 && db.getConfig().autoApproveSafe) {
    persistLog(auditLog);
    await forwardToolCall(message.id, mapping.serverName, mapping.originalName, args, auditLog, session, category);
    return;
  }

  auditLog.status = 'pending';
  auditLog.reason = uniqueReasons(reasons).join('; ') || 'Manual confirmation required';
  auditLog.evidence = deduplicateEvidence(evidence);
  persistLog(auditLog);
  if (!wsConnected) {
    auditLog.status = 'block';
    auditLog.reason = 'Blocked: approval interface is offline';
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, 'Execution blocked because approval interface is offline');
    return;
  }

  const requestedAt = new Date();
  const expiresAt = new Date(requestedAt.getTime() + limits().approvalTimeoutMs);
  const approval = createApprovalView(auditLog, session.policy, requestedAt.toISOString(), expiresAt.toISOString());
  auditLog.approval = {
    actionFingerprint: approval.actionFingerprint,
    requestedAt: approval.requestedAt,
    expiresAt: approval.expiresAt
  };
  persistLog(auditLog);
  const approvalResult = waitForApproval(auditLog, approval.actionFingerprint, expiresAt.getTime());
  sendToExtension({
    type: 'approve_request',
    approval,
    driftDetails: isDrift && baseline ? { oldHash: baseline.hash, newHash: baseline.observedHash || baseline.hash } : undefined
  });

  const approved = await approvalResult;
  if (!approved) {
    auditLog.status = 'block';
    if (auditLog.approval?.userResponse === 'deny') auditLog.reason = 'Blocked by user';
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, auditLog.reason);
    return;
  }

  auditLog.status = 'allow';
  auditLog.reason = `${auditLog.reason}; approved once by user`;
  persistLog(auditLog);
  await forwardToolCall(message.id, mapping.serverName, mapping.originalName, args, auditLog, session, category);
}

function sessionState(sessionId: string, policy: SessionPolicy): SessionState {
  const now = Date.now();
  const existing = sessions.get(sessionId);
  if (!existing || now - existing.lastCallTime > SESSION_TIMEOUT_MS) {
    const created = { categories: [], lastCallTime: now, dataFlow: createDataFlowState(), policy };
    sessions.set(sessionId, created);
    return created;
  }
  return existing;
}

function waitForApproval(log: AuditLog, actionFingerprint: string, expiresAt: number): Promise<boolean> {
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      pendingApprovals.delete(log.id);
      log.status = 'block';
      log.reason = 'Blocked: approval request timed out';
      if (log.approval) log.approval.userResponse = 'expired';
      persistLog(log);
      resolve(false);
    }, Math.max(0, expiresAt - Date.now()));
    pendingApprovals.set(log.id, { timer, resolve, log, actionFingerprint, expiresAt });
  });
}

async function forwardToolCall(
  clientId: JsonRpcId,
  serverName: string,
  toolName: string,
  args: unknown,
  auditLog: AuditLog,
  session: SessionState,
  category: string
): Promise<void> {
  try {
    const response = await requestDownstream(serverName, 'tools/call', { name: toolName, arguments: args });
    if (response.error) {
      writeToClient({ jsonrpc: '2.0', id: clientId, error: response.error });
      return;
    }

    const outputEventId = `result:${auditLog.sessionId || 'default'}:${crypto.randomUUID()}`;
    const outputInspection = inspectStructuredText(
      response.result,
      'mcp.tool-result',
      outputEventId,
      limits().maxScanStrings
    );
    const outputEvidence = outputInspection.evidence.filter(finding => !acceptedRisks.isAccepted(finding));
    const inheritedLabels: DataLabel[] = category === 'READ_NETWORK' ? ['untrusted'] : [];
    const dataLabels = recordOutput(session.dataFlow, response.result, inheritedLabels);
    auditLog.dataLabels = Array.from(new Set([...(auditLog.dataLabels || []), ...dataLabels]));
    auditLog.evidence = deduplicateEvidence([...(auditLog.evidence || []), ...outputEvidence]);
    auditLog.inspection = mergeInspection(
      auditLog.inspection,
      inspectionSummary(
        outputInspection.stringsInspected,
        outputInspection.truncated,
        outputInspection.truncated ? 'Tool-result string limit reached' : undefined
      )
    );

    let semanticIncomplete = false;
    if (db.getConfig().geminiApiKey) {
      const semantic = await scanSemanticSandboxed(
        toolName,
        JSON.stringify(response.result),
        db.getConfig().geminiApiKey!,
        Math.min(limits().requestTimeoutMs, 4_000)
      );
      if (semantic.suspicious) {
        outputEvidence.push(makeEvidence(
          'mcp.semantic-sandbox',
          undefined,
          'high',
          semantic.reason || 'Semantic scan flagged tool output',
          outputEventId
        ));
      }
      semanticIncomplete = !semantic.complete;
      if (semanticIncomplete) {
        auditLog.inspection.complete = false;
        auditLog.inspection.partial += 1;
        auditLog.inspection.total += 1;
        auditLog.inspection.reasons.push(semantic.reason || 'Semantic output inspection incomplete');
      }
    }

    const dangerousOutput = outputInspection.truncated || outputEvidence.some(finding =>
      finding.severity === 'high' || finding.severity === 'critical'
    );
    if (dangerousOutput) {
      auditLog.status = 'block';
      auditLog.promptInjection = outputEvidence.length > 0 || undefined;
      auditLog.evidence = deduplicateEvidence([...(auditLog.evidence || []), ...outputEvidence]);
      auditLog.reason = uniqueReasons([
        auditLog.reason || '',
        ...outputEvidence.map(finding => finding.message),
        outputInspection.truncated ? 'Tool output inspection was incomplete' : ''
      ]).join('; ');
      persistLog(auditLog);
      writeError(clientId, -32603, 'Tool output blocked by Agent Guardian', {
        reason: auditLog.reason,
        evidenceIds: outputEvidence.map(finding => finding.id)
      });
      return;
    }

    if (semanticIncomplete) {
      auditLog.reason = uniqueReasons([auditLog.reason || '', 'Semantic output inspection incomplete']).join('; ');
    }
    persistLog(auditLog);
    writeToClient({ jsonrpc: '2.0', id: clientId, result: response.result });
  } catch (error) {
    writeError(clientId, -32001, error instanceof Error ? error.message : 'Downstream tool call failed');
  }
}

function inspectionSummary(stringsInspected: number, truncated: boolean, reason?: string): InspectionSummary {
  return {
    complete: !truncated,
    total: 1,
    completed: truncated ? 0 : 1,
    partial: truncated ? 1 : 0,
    skipped: 0,
    failed: 0,
    outOfScope: 0,
    reasons: reason ? [reason] : []
  };
}

function mergeInspection(
  first: InspectionSummary | undefined,
  second: InspectionSummary
): InspectionSummary {
  if (!first) return second;
  return {
    complete: first.complete && second.complete,
    total: first.total + second.total,
    completed: first.completed + second.completed,
    partial: first.partial + second.partial,
    skipped: first.skipped + second.skipped,
    failed: first.failed + second.failed,
    outOfScope: first.outOfScope + second.outOfScope,
    reasons: uniqueReasons([...first.reasons, ...second.reasons])
  };
}

function makeEvidence(
  detectorId: string,
  ruleId: string | undefined,
  severity: Evidence['severity'],
  message: string,
  eventId: string,
  metadata?: Record<string, unknown>
): Evidence {
  return {
    id: crypto.createHash('sha256').update(`${detectorId}\0${ruleId || ''}\0${eventId}\0${message}`).digest('hex'),
    detectorId,
    detectorVersion: '1.0.0',
    ruleId,
    severity,
    confidence: 1,
    message,
    eventIds: [eventId],
    provenance: { lane: 'mcp' },
    metadata
  };
}

function deduplicateEvidence(evidence: Evidence[]): Evidence[] {
  return Array.from(new Map(evidence.map(finding => [finding.id, finding])).values());
}

function uniqueReasons(reasons: string[]): string[] {
  return Array.from(new Set(reasons.map(reason => reason.trim()).filter(Boolean)));
}

function persistLog(log: AuditLog): void {
  db.addLog(log);
  sendToExtension({ type: 'log', log });
}

async function shutdown(reason: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error(`[MCP-Guardian-Proxy] Shutting down: ${reason}`);
  if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
  ws?.close();
  ws = null;
  wsConnected = false;

  for (const pending of pendingApprovals.values()) {
    clearTimeout(pending.timer);
    pending.log.status = 'block';
    pending.log.reason = 'Blocked: Guardian shut down before approval';
    db.addLog(pending.log);
    pending.resolve(false);
  }
  pendingApprovals.clear();

  for (const pending of pendingDownstream.values()) {
    clearTimeout(pending.timer);
    pending.reject(new Error('Guardian shut down'));
  }
  pendingDownstream.clear();

  for (const name of Array.from(downstreams.keys())) stopDownstreamServer(name, reason);
}


connectToExtension();
if (WS_DISABLED || WORKSPACE_SETTINGS_PATH) {
  // The explicit workspace settings are already loaded, so discovery can start
  // without waiting for a VS Code extension to connect.
  syncDownstreamServers();
} else {
  // Defer server startup until the extension pushes an update_config message.
  // This ensures workspace settings.json values (e.g. the filesystem server)
  // override whatever is in the global ~/.mcp-guardian db.
  // Fall back to the on-disk config after 3 seconds if the extension never connects.
  startupSyncTimer = setTimeout(() => {
    console.error('[MCP-Guardian-Proxy] Extension did not send config within 3 s; starting servers from on-disk config.');
    startupSyncTimer = undefined;
    syncDownstreamServers();
  }, 3_000);
}
console.error('[MCP-Guardian-Proxy] Standalone proxy active on stdin/stdout.');
