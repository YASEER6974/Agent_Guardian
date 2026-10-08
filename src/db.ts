import * as fs from 'fs';
import * as path from 'path';
import { ToolBaseline, AuditLog, GuardianConfig } from './types';

export class GuardianDb {
  private filePath: string;
  private data: {
    baselines: Record<string, Record<string, ToolBaseline>>; // serverName -> toolName -> Baseline
    logs: AuditLog[];
    config: GuardianConfig;
  };

  constructor(storagePath: string) {
    this.filePath = path.join(storagePath, 'mcp-guardian-db.json');
    this.ensureDirectoryExists(storagePath);
    this.data = this.load();
  }

  refresh(): void {
    this.data = this.load();
  }

  // Runtime snapshots received by the dashboard are read-only mirrors.
  mirrorState(state: { baselines: Record<string, Record<string, ToolBaseline>>; logs: AuditLog[]; config: GuardianConfig }): void {
    this.data = structuredClone(state);
  }

  mirrorLog(log: AuditLog): void {
    this.upsertLog(log);
  }

  private ensureDirectoryExists(dir: string) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  private load(): typeof this.data {
    const defaultConfig = {
      servers: [
        {
          name: 'everything',
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-everything']
        }
      ],
      forbiddenTransitions: [
        ['READ_LOCAL', 'WRITE_COMMUNICATION'],
        ['READ_FINANCIAL', 'WRITE_COMMUNICATION'],
        ['READ_LOCAL', 'EXECUTE_SYSTEM'],
        ['READ_NETWORK', 'EXECUTE_SYSTEM']
      ] as [string, string][],
      geminiApiKey: '',
      autoApproveSafe: true,
      firstSeenPolicy: 'approve-safe' as const,
      sessionPolicy: {
        intent: '',
        allowedCapabilities: [],
        trustedDestinations: []
      }
    };

    if (fs.existsSync(this.filePath)) {
      try {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        return {
          baselines: migrateBaselines(parsed.baselines || {}),
          logs: parsed.logs || [],
          config: { ...defaultConfig, ...(parsed.config || {}) }
        };
      } catch (e) {
        console.error('Failed to parse database, using defaults', e);
      }
    }

    const initial = {
      baselines: {},
      logs: [],
      config: defaultConfig
    };
    this.save(initial);
    return initial;
  }

  private save(dataToSave = this.data) {
    const stagingPath = `${this.filePath}.guardian-${process.pid}.tmp`;
    try {
      fs.writeFileSync(stagingPath, JSON.stringify(dataToSave, null, 2), 'utf-8');
      fs.renameSync(stagingPath, this.filePath);
    } catch (e) {
      console.error('Failed to write database file', e);
      if (fs.existsSync(stagingPath)) fs.unlinkSync(stagingPath);
    }
  }

  // Configurations
  getConfig(): GuardianConfig {
    return this.data.config;
  }

  updateConfig(config: Partial<GuardianConfig>) {
    this.refresh();
    this.data.config = { ...this.data.config, ...config };
    this.save();
  }

  // Baselines
  getBaselines(): Record<string, Record<string, ToolBaseline>> {
    return this.data.baselines;
  }

  getToolBaseline(serverName: string, toolName: string): ToolBaseline | undefined {
    return this.data.baselines[serverName]?.[toolName];
  }

  setToolBaseline(serverName: string, toolName: string, baseline: ToolBaseline) {
    this.refresh();
    if (!this.data.baselines[serverName]) {
      this.data.baselines[serverName] = {};
    }
    this.data.baselines[serverName][toolName] = baseline;
    this.save();
  }

  applyDiscovery(serverName: string, baselines: Record<string, ToolBaseline>, logs: AuditLog[]): void {
    // One bounded commit per discovery, rather than rewriting a multi-megabyte
    // provider database once for every tool. Preserve unrelated latest records.
    this.refresh();
    this.data.baselines[serverName] = { ...(this.data.baselines[serverName] || {}), ...baselines };
    for (const log of logs) this.upsertLog(log);
    this.save();
  }

  approveDrift(serverName: string, toolName: string, newHash: string): boolean {
    this.refresh();
    const baseline = this.getToolBaseline(serverName, toolName);
    if (baseline?.observedHash && baseline.observedDefinition && baseline.observedHash === newHash &&
      ['drifted', 'pending'].includes(baseline.status || '') && baseline.inspection?.complete === true &&
      !(baseline.evidence || []).length) {
      baseline.hash = baseline.observedHash;
      baseline.description = baseline.observedDefinition.description;
      baseline.inputSchema = baseline.observedDefinition.inputSchema;
      baseline.trustedDefinition = baseline.observedDefinition;
      baseline.approved = true;
      baseline.status = 'approved';
      baseline.differences = [];
      baseline.lastSeen = new Date().toISOString();
      this.save();
      return true;
    }
    return false;
  }

  setToolCategory(serverName: string, toolName: string, category: string) {
    this.refresh();
    const baseline = this.getToolBaseline(serverName, toolName);
    if (baseline) {
      baseline.category = category;
      this.save();
    }
  }

  // Logs
  getLogs(): AuditLog[] {
    return this.data.logs;
  }

  addLog(log: AuditLog) {
    this.refresh();
    this.upsertLog(log);
    this.save();
  }

  private upsertLog(log: AuditLog) {
    const existingIndex = this.data.logs.findIndex(existing => existing.id === log.id);
    if (existingIndex >= 0) {
      this.data.logs[existingIndex] = { ...this.data.logs[existingIndex], ...log };
    } else {
      this.data.logs.unshift(log);
    }
    // Limit to last 500 logs to prevent memory bloat
    if (this.data.logs.length > 500) {
      this.data.logs.pop();
    }
  }

  clearLogs() {
    this.refresh();
    this.data.logs = [];
    this.save();
  }

  // Full raw state for sync
  getRawState() {
    return this.data;
  }
}

function migrateBaselines(
  baselines: Record<string, Record<string, ToolBaseline>>
): Record<string, Record<string, ToolBaseline>> {
  for (const tools of Object.values(baselines)) {
    for (const baseline of Object.values(tools)) {
      baseline.status ??= baseline.approved ? 'approved' : 'pending';
      baseline.trustedDefinition ??= {
        name: baseline.name,
        description: baseline.description || '',
        inputSchema: baseline.inputSchema || {}
      };
      baseline.observedDefinition ??= baseline.trustedDefinition;
      baseline.observedHash ??= baseline.hash;
      baseline.differences ??= [];
    }
  }
  return baselines;
}
