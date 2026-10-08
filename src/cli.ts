import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { GuardianDb } from './db';
import { validateServer } from './server-config';
import { readWorkspaceSettings } from './workspace-settings';
import { applyEdits, modify } from 'jsonc-parser/lib/esm/main';
import { parseAuditExport, ReportFormat, serializeReport, verifyAuditExport } from './reporting';

export const EXIT_OK = 0;
export const EXIT_USAGE = 2;
export const EXIT_INTEGRITY = 3;
export const EXIT_IO = 4;

function main(args = process.argv.slice(2)): number {
  try {
    if (args.includes('--help') || args.length === 0) {
      process.stdout.write(help());
      return EXIT_OK;
    }
    const [command, operation] = args;
    if (command === 'proxy') {
      // Keep the proxy in its own bundle so the npm CLI and VS Code extension use
      // exactly the same runtime. Requiring it starts the stdio transport.
      require(path.join(__dirname, 'proxy.js'));
      return EXIT_OK;
    }
    if (command === 'config') {
      if (operation === 'add-server') return addServer(args.slice(2));
      if (operation === 'show') return showConfig(args.slice(2));
      return usage(`Unknown config operation '${operation || ''}'`);
    }
    if (command !== 'report') return usage(`Unknown command '${command}'`);
    if (operation === 'export') return exportReport(args.slice(2));
    if (operation === 'verify') return verifyReport(args.slice(2));
    return usage(`Unknown report operation '${operation || ''}'`);
  } catch (error) {
    process.stderr.write(`Agent Guardian: ${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT_IO;
  }
}

function addServer(args: string[]): number {
  const name = option(args, '--name');
  const command = option(args, '--command');
  const url = option(args, '--url');
  const argsJson = option(args, '--args-json') || '[]';
  if (!name || (!command && !url) || (command && url)) return usage('add-server requires --name and either --command or --url');
  const serverArgs = JSON.parse(argsJson);
  if (!Array.isArray(serverArgs) || serverArgs.some(item => typeof item !== 'string')) {
    return usage('--args-json must be a JSON array of strings');
  }
  const database = databaseFor(args);
  const settingsPath = option(args, '--workspace-settings') || process.env.MCP_GUARDIAN_WORKSPACE_SETTINGS_PATH;
  if (settingsPath) database.updateConfig(readWorkspaceSettings(settingsPath, database.getConfig()));
  const headers = JSON.parse(option(args, '--headers-json') || '{}');
  const server = validateServer(url ? { name, type: 'http', url, ...(Object.keys(headers).length ? { headers } : {}) }
    : { name, command, args: serverArgs });
  const servers = [...database.getConfig().servers.filter(server => server.name !== name), server];
  if (settingsPath) {
    const original = fs.readFileSync(settingsPath, 'utf8');
    fs.writeFileSync(settingsPath, applyEdits(original, modify(original, ['mcp-guardian.servers'], servers, { formattingOptions: { insertSpaces: true, tabSize: 2 } })), 'utf8');
  }
  database.updateConfig({ servers });
  process.stdout.write(`Configured downstream MCP server '${name}'\n`);
  return EXIT_OK;
}

function showConfig(args: string[]): number {
  const config = structuredClone(databaseFor(args).getConfig());
  if (config.geminiApiKey) config.geminiApiKey = '[configured]';
  for (const server of config.servers) {
    if (server.headers) server.headers = Object.fromEntries(Object.keys(server.headers).map(key => [key, '[REDACTED]']));
    if (server.env) server.env = Object.fromEntries(Object.keys(server.env).map(key => [key, '[REDACTED]']));
  }
  process.stdout.write(`${JSON.stringify(config, null, 2)}\n`);
  return EXIT_OK;
}

function databaseFor(args: string[]): GuardianDb {
  const storage = option(args, '--storage') || process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
  return new GuardianDb(path.resolve(storage));
}

function exportReport(args: string[]): number {
  const format = option(args, '--format') as ReportFormat | undefined;
  const output = option(args, '--out');
  const storage = option(args, '--storage') || process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
  if (!format || !['json', 'jsonl', 'sarif'].includes(format)) return usage('Use --format json, jsonl, or sarif');
  if (!output) return usage('Missing --out path');
  const database = new GuardianDb(path.resolve(storage));
  fs.writeFileSync(path.resolve(output), serializeReport(database.getLogs(), format), 'utf8');
  process.stdout.write(`Exported ${database.getLogs().length} audit entries to ${path.resolve(output)}\n`);
  return EXIT_OK;
}

function verifyReport(args: string[]): number {
  const input = option(args, '--input');
  if (!input) return usage('Missing --input path');
  const records = parseAuditExport(fs.readFileSync(path.resolve(input), 'utf8'));
  if (!verifyAuditExport(records)) {
    process.stderr.write('Audit integrity verification failed\n');
    return EXIT_INTEGRITY;
  }
  process.stdout.write(`Audit integrity verified (${records.length} records)\n`);
  return EXIT_OK;
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function usage(message: string): number {
  process.stderr.write(`${message}\n\n${help()}`);
  return EXIT_USAGE;
}

function help(): string {
  return [
    'Agent Guardian CLI',
    '',
    '  agent-guardian proxy',
    '  agent-guardian config add-server --name <name> --command <command> [--args-json <json>] [--storage <directory>]',
    '  agent-guardian config add-server --name <name> --url <http-mcp-url> [--headers-json <json>] [--storage <directory>] [--workspace-settings <file>]',
    '  agent-guardian config show [--storage <directory>]',
    '  agent-guardian report export --format json|jsonl|sarif --out <file> [--storage <directory>]',
    '  agent-guardian report verify --input <json-or-jsonl-file>',
    '',
    `Exit codes: ${EXIT_OK}=success, ${EXIT_USAGE}=usage, ${EXIT_INTEGRITY}=integrity failure, ${EXIT_IO}=I/O failure`,
    ''
  ].join('\n');
}

process.exitCode = main();
