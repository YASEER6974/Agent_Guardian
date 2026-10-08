import * as os from 'os';
import * as path from 'path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { BrowserMcpService } from './browser/mcp-service';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const values = (name: string) => args.flatMap((item, index) => item === name ? [args[index + 1]] : []);
  const allowedOrigins = values('--allowed-origin').map(origin);
  const trustedOrigins = values('--trusted-origin').map(origin);
  if (!allowedOrigins.length || trustedOrigins.some(item => !allowedOrigins.includes(item))) {
    throw new Error('Specify --allowed-origin <origin>; trusted origins must be a subset of allowed origins');
  }
  const storagePath = values('--storage')[0] || process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
  const sessionId = values('--session')[0] || 'default';
  const allowForms = args.includes('--allow-forms');
  const service = new BrowserMcpService({
    storagePath, sessionId, allowedOrigins, trustedOrigins, allowForms, headless: !args.includes('--headed'),
    sessionPolicy: {
      intent: 'Read external pages through Browser Guardian; use synthetic demo forms only when explicitly enabled.',
      allowedCapabilities: ['BROWSER_NAVIGATE', 'BROWSER_NETWORK_REQUEST', ...(allowForms ? ['BROWSER_FILL', 'BROWSER_SUBMIT_FORM'] : [])],
      trustedDestinations: trustedOrigins
    }
  });
  const server = new Server({ name: 'agent-guardian-browser', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: service.tools() }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    try {
      const result = await service.call(request.params.name, request.params.arguments || {});
      return { isError: result.outcome !== 'ALLOW', content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
    } catch {
      return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify({
        outcome: 'ERROR', contentWithheld: true,
        explanation: 'Browser operation failed or arguments were invalid. No page content released. Check the configured origin and page selector.'
      }) }] };
    }
  });
  const transport = new StdioServerTransport();
  server.onclose = () => { void service.close(); };
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void server.close(); });
  await server.connect(transport);
  process.stderr.write('[Browser-Guardian] Guarded browser MCP ready; page scripts disabled; origins explicitly scoped.\n');
}

function origin(value: string): string {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Origins must be plain HTTP(S) origins without paths, credentials or queries');
  }
  return url.origin;
}

void main().catch(error => {
  process.stderr.write(`Browser Guardian startup failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
