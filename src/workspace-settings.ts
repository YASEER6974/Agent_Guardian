import * as fs from 'fs';
import { DownstreamServerConfig, GuardianConfig } from './types';
import { parse, ParseError } from 'jsonc-parser/lib/esm/main';
import { validateServer } from './server-config';

// Use the same explicit workspace configuration in the extension and proxy,
// even when a development host opens without a folder.
export function readWorkspaceSettings(settingsPath: string, current: GuardianConfig): Partial<GuardianConfig> {
  const errors: ParseError[] = [];
  const settings = parse(fs.readFileSync(settingsPath, 'utf8'), errors, { allowTrailingComma: true }) as Record<string, unknown>;
  if (errors.length || !settings || typeof settings !== 'object') throw new Error(`Invalid Guardian workspace settings: ${settingsPath}`);
  const servers = settings['mcp-guardian.servers'];
  if (!Array.isArray(servers)) {
    throw new Error(`Workspace Guardian settings contain no valid downstream servers: ${settingsPath}`);
  }
  servers.forEach(validateServer);
  return {
    servers: servers as DownstreamServerConfig[],
    ...(Array.isArray(settings['mcp-guardian.forbiddenTransitions'])
      ? { forbiddenTransitions: settings['mcp-guardian.forbiddenTransitions'] as [string, string][] } : {}),
    ...(typeof settings['mcp-guardian.geminiApiKey'] === 'string'
      ? { geminiApiKey: settings['mcp-guardian.geminiApiKey'] as string } : {}),
    autoApproveSafe: typeof settings['mcp-guardian.autoApproveSafe'] === 'boolean'
      ? settings['mcp-guardian.autoApproveSafe'] : current.autoApproveSafe,
    sessionPolicy: {
      intent: typeof settings['mcp-guardian.sessionIntent'] === 'string'
        ? settings['mcp-guardian.sessionIntent'] : current.sessionPolicy?.intent || '',
      allowedCapabilities: Array.isArray(settings['mcp-guardian.allowedCapabilities'])
        ? settings['mcp-guardian.allowedCapabilities'] as string[] : current.sessionPolicy?.allowedCapabilities || [],
      trustedDestinations: Array.isArray(settings['mcp-guardian.trustedDestinations'])
        ? settings['mcp-guardian.trustedDestinations'] as string[] : current.sessionPolicy?.trustedDestinations || []
    }
  };
}
