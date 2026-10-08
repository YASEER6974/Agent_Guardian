import * as os from 'os';
import * as path from 'path';
import { GuardedBrowserHarness } from './browser/playwright-harness';
import { browserDecisionReport } from './browser/mcp-service';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const url = option(args, '--url');
  if (!url) throw new Error('Usage: agent-guardian-browser --url <url> [--session <id>] [--trusted-origin <origin>]');
  const storagePath = option(args, '--storage') || process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
  const sessionId = option(args, '--session') || 'browser-default';
  const trustedOrigin = option(args, '--trusted-origin');
  const harness = new GuardedBrowserHarness({
    storagePath,
    sessionId,
    trustedOrigins: trustedOrigin ? [trustedOrigin] : [],
    headless: !args.includes('--headed')
  });
  try {
    await harness.start();
    const navigation = await harness.navigate(url);
    if (navigation.outcome !== 'ALLOW') {
      process.stdout.write(`${JSON.stringify({ navigation }, null, 2)}\n`);
      process.exitCode = navigation.outcome === 'BLOCK' ? 3 : 2;
      return;
    }
    const observation = await harness.observe();
    process.stdout.write(`${JSON.stringify(observation.decision.outcome === 'ALLOW' ? observation : browserDecisionReport(observation.decision), null, 2)}\n`);
    if (observation.decision.outcome !== 'ALLOW') process.exitCode = observation.decision.outcome === 'BLOCK' ? 3 : 2;
  } finally {
    await harness.close();
  }
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

void main().catch(error => {
  process.stderr.write(`Agent Guardian Browser: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 4;
});
