import * as fs from 'fs';
import * as path from 'path';
import { applyEdits, modify, parse, ParseError } from 'jsonc-parser/lib/esm/main';
import { DownstreamServerConfig } from './types';
import { validateServer } from './server-config';

function readConfig(file: string): { text: string; value: any } {
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '{}';
  const errors: ParseError[] = [];
  const value = parse(text, errors, { allowTrailingComma: true });
  if (errors.length || !value || Array.isArray(value) || typeof value !== 'object') throw new Error(`Invalid JSON configuration: ${file}`);
  return { text, value };
}

export function saveExternalServer(settingsPath: string, server: DownstreamServerConfig): void {
  validateServer(server);
  const { text, value } = readConfig(settingsPath);
  const existing = value['mcp-guardian.servers'] || [];
  if (!Array.isArray(existing)) throw new Error('Guardian servers configuration must be an array');
  const servers = [...existing.filter((item: DownstreamServerConfig) => item.name !== server.name), server];
  servers.forEach(validateServer);
  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, applyEdits(text, modify(text, ['mcp-guardian.servers'], servers,
    { formattingOptions: { insertSpaces: true, tabSize: 2 } })), 'utf8');
}

export function routeWorkspaceServers(workspaceRoot: string, guardianDefinition: unknown): { imported: number; backup?: string } {
  return routeServers(path.join(workspaceRoot, '.vscode', 'mcp.json'),
    path.join(workspaceRoot, '.vscode', 'settings.json'), workspaceRoot, guardianDefinition, 'servers');
}

export function routeAntigravityServers(mcpPath: string, workspaceRoot: string, guardianDefinition: unknown,
  connectionSettings: Record<string, unknown> = {}): { imported: number; backup?: string } {
  if (!fs.existsSync(mcpPath)) throw new Error('Antigravity config not found; use the file opened by View raw config');
  return routeServers(mcpPath, path.join(workspaceRoot, '.vscode', 'settings.json'),
    workspaceRoot, guardianDefinition, 'mcpServers', connectionSettings);
}

function routeServers(mcpPath: string, settingsPath: string, workspaceRoot: string, guardianDefinition: unknown,
  serverKey: string, connectionSettings: Record<string, unknown> = {}): { imported: number; backup?: string } {
  const mcp = readConfig(mcpPath);
  const settings = readConfig(settingsPath);
  const current: DownstreamServerConfig[] = settings.value['mcp-guardian.servers'] || [];
  if (!Array.isArray(current)) throw new Error('Guardian servers configuration must be an array');
  const configured = mcp.value[serverKey] || {};
  if (Array.isArray(configured) || typeof configured !== 'object') throw new Error('MCP servers configuration must be an object');
  let imported = 0;
  const merged = [...current];
  for (const [name, definition] of Object.entries(configured)) {
    if (name === 'agent-guardian' || name === 'mcp-guardian') continue;
    const item = definition as any;
    if (!item || Array.isArray(item) || typeof item !== 'object') throw new Error(`Invalid server '${name}'`);
    // Never silently remove authentication, disabled tools or client-specific
    // constraints when moving a connection behind the proxy.
    for (const key of Object.keys(item)) {
      if (!['type', 'command', 'args', 'cwd', 'env', 'url', 'serverUrl', 'headers'].includes(key)) {
        throw new Error(`'${name}' uses unsupported '${key}'; routing aborted without changing files. OAuth needs a supported authenticated transport.`);
      }
    }
    if (item.type && !['http', 'stdio'].includes(item.type)) throw new Error(`Unsupported transport for '${name}'; use Streamable HTTP or stdio`);
    const expanded = JSON.stringify(item).replace(/\$\{workspaceFolder\}/g, () => workspaceRoot.replace(/\\/g, '\\\\'));
    if (/\$\{input:/.test(expanded)) throw new Error(`'${name}' uses interactive inputs; replace them with environment variables before routing`);
    const values = JSON.parse(expanded);
    const downstreamName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
    if (merged.some(server => server.name === downstreamName)) throw new Error(`Guardian already has '${downstreamName}'; rename one server before importing`);
    if ((values.url || values.serverUrl) && values.command) throw new Error(`'${name}' has ambiguous transports`);
    if ((values.url || values.serverUrl) && (values.env || values.args || values.cwd)) {
      throw new Error(`'${name}' has unsupported HTTP process settings; use environment references in headers`);
    }
    const server = validateServer(values.url || values.serverUrl
      ? { name: downstreamName, type: 'http', url: values.url || values.serverUrl, ...(values.headers ? { headers: values.headers } : {}) }
      : { name: downstreamName, command: values.command, cwd: values.cwd || workspaceRoot, args: values.args || [], ...(values.env ? { env: values.env } : {}) });
    merged.push(server);
    imported++;
  }
  merged.forEach(validateServer);
  const options = { formattingOptions: { insertSpaces: true, tabSize: 2 } };
  let newSettings = applyEdits(settings.text, modify(settings.text, ['mcp-guardian.servers'], merged, options));
  for (const [key, value] of Object.entries(connectionSettings)) newSettings = applyEdits(newSettings, modify(newSettings, [key], value, options));
  const newMcp = applyEdits(mcp.text, modify(mcp.text, [serverKey], { 'agent-guardian': guardianDefinition }, options));
  fs.mkdirSync(path.dirname(mcpPath), { recursive: true });
  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  const backup = fs.existsSync(mcpPath) ? `${mcpPath}.guardian-backup-${Date.now()}` : undefined;
  if (backup) fs.copyFileSync(mcpPath, backup, fs.constants.COPYFILE_EXCL);
  fs.writeFileSync(settingsPath, newSettings, 'utf8');
  try { fs.writeFileSync(mcpPath, newMcp, 'utf8'); }
  catch (error) { fs.writeFileSync(settingsPath, settings.text, 'utf8'); throw error; }
  return { imported, backup };
}
