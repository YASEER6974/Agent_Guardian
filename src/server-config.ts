import { DownstreamServerConfig } from './types';

export function isHttpServer(server: DownstreamServerConfig): boolean {
  return server.type === 'http' || typeof server.url === 'string';
}

export function validateServer(value: unknown): DownstreamServerConfig {
  const server = value as DownstreamServerConfig;
  if (!server || typeof server.name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(server.name)) {
    throw new Error('Server name must use letters, numbers, underscores or hyphens');
  }
  if (server.type !== undefined && !['stdio', 'http'].includes(server.type)) throw new Error('Unsupported MCP transport');
  if (isHttpServer(server)) {
    if (typeof server.url !== 'string' || !server.url || server.command || server.type === 'stdio') {
      throw new Error(`HTTP MCP server '${server.name}' requires a URL and no local command`);
    }
    const url = new URL(server.url);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) {
      throw new Error('Use an HTTP(S) MCP endpoint without embedded credentials or a fragment');
    }
  } else if (typeof server.command !== 'string' || !server.command ||
      (server.args !== undefined && (!Array.isArray(server.args) || server.args.some(arg => typeof arg !== 'string')))) {
    throw new Error(`Local MCP server '${server.name}' requires a command and string arguments`);
  }
  for (const fields of [server.headers, server.env]) {
    if (fields !== undefined && (!fields || Array.isArray(fields) || typeof fields !== 'object' ||
      Object.values(fields).some(value => typeof value !== 'string'))) throw new Error('Headers and environment values must be strings');
  }
  if (server.cwd !== undefined && typeof server.cwd !== 'string') throw new Error('The MCP working directory must be a string');
  return server;
}

export function resolveHttpHeaders(server: DownstreamServerConfig): Record<string, string> {
  return Object.fromEntries(Object.entries(server.headers || {}).map(([key, value]) => [key, resolveEnvironmentReferences(value)]));
}

export function resolveEnvironmentReferences(value: string): string {
  return value.replace(/\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, name: string) => {
      const resolved = process.env[name];
      if (!resolved) throw new Error(`Missing environment variable '${name}' for MCP authentication`);
      return resolved;
    });
}
