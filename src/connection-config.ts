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
  const mcpPath = path.join(workspaceRoot, '.vscode', 'mcp.json');
  const settingsPath = path.join(workspaceRoot, '.vscode', 'settings.json');
  const mcp = readConfig(mcpPath);
  const settings = readConfig(settingsPath);
  const current: DownstreamServerConfig[] = settings.value['mcp-guardian.servers'] || [];
  if (!Array.isArray(current)) throw new Error('Guardian servers configuration must be an array');
  const configured = mcp.value.servers || {};
  if (Array.isArray(configured) || typeof configured !== 'object') throw new Error('MCP servers configuration must be an object');
  let imported = 0;
  const merged = [...current];
  for (const [name, definition] of Object.entries(configured)) {
    if (name === 'agent-guardian' || name === 'mcp-guardian') continue;
    const item = definition as any;
    if (item.type && !['http', 'stdio'].includes(item.type)) throw new Error(`Unsupported transport for '${name}'; use Streamable HTTP or stdio`);
    const expanded = JSON.stringify(item).replace(/\$\{workspaceFolder\}/g, () => workspaceRoot.replace(/\\/g, '\\\\'));
    if (/\$\{input:/.test(expanded)) throw new Error(`'${name}' uses interactive inputs; replace them with environment variables before routing`);
    const values = JSON.parse(expanded);
    const downstreamName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
    if (merged.some(server => server.name === downstreamName)) throw new Error(`Guardian already has '${downstreamName}'; rename one server before importing`);
    const server = validateServer(values.url
      ? { name: downstreamName, type: 'http', url: values.url, ...(values.headers ? { headers: values.headers } : {}) }
      : { name: downstreamName, command: values.command, cwd: values.cwd || workspaceRoot, args: values.args || [], ...(values.env ? { env: values.env } : {}) });
    merged.push(server);
    imported++;
  }
  merged.forEach(validateServer);
  const options = { formattingOptions: { insertSpaces: true, tabSize: 2 } };
  const newSettings = applyEdits(settings.text, modify(settings.text, ['mcp-guardian.servers'], merged, options));
  const newMcp = applyEdits(mcp.text, modify(mcp.text, ['servers'], { 'agent-guardian': guardianDefinition }, options));
  fs.mkdirSync(path.dirname(mcpPath), { recursive: true });
  const backup = fs.existsSync(mcpPath) ? `${mcpPath}.guardian-backup-${Date.now()}` : undefined;
  if (backup) fs.copyFileSync(mcpPath, backup);
  fs.writeFileSync(settingsPath, newSettings, 'utf8');
  try { fs.writeFileSync(mcpPath, newMcp, 'utf8'); }
  catch (error) { fs.writeFileSync(settingsPath, settings.text, 'utf8'); throw error; }
  return { imported, backup };
}
