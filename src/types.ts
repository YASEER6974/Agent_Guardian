import type { DataLabel, Evidence, InspectionSummary } from './core/types';

export interface DownstreamServerConfig {
  name: string;
  type?: 'stdio' | 'http';
  command?: string;
  cwd?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
}

export interface ResourceLimits {
  maxMessageBytes: number;
  maxNestingDepth: number;
  requestTimeoutMs: number;
  approvalTimeoutMs: number;
  maxScanStrings?: number;
  maxDiffEntries?: number;
}

export interface SessionPolicy {
  intent: string;
  allowedCapabilities: string[];
  trustedDestinations: string[];
}

export interface ApprovalRequestView {
  id: string;
  actionFingerprint: string;
  requestedAt: string;
  expiresAt: string;
  sessionId: string;
  intent: string;
  serverName: string;
  toolName: string;
  capability: string;
  destination?: string;
  reason: string;
  arguments: unknown;
  evidence: Array<{ id: string; ruleId?: string; severity: string; message: string }>;
}

export interface ToolDefinitionSnapshot {
  name: string;
  title?: string;
  description: string;
  inputSchema: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
  metadata?: unknown;
}

export interface SchemaDifference {
  path: string;
  kind: 'added' | 'removed' | 'changed';
  before?: unknown;
  after?: unknown;
}

export interface ToolBaseline {
  name: string;
  description: string;
  inputSchema: any;
  hash: string;
  category: string;
  approved: boolean;
  firstSeen: string;
  lastSeen: string;
  status?: 'approved' | 'pending' | 'drifted' | 'rejected';
  trustedDefinition?: ToolDefinitionSnapshot;
  observedDefinition?: ToolDefinitionSnapshot;
  observedHash?: string;
  differences?: SchemaDifference[];
  inspection?: InspectionSummary;
  evidence?: Evidence[];
}

export interface AuditLog {
  id: string;
  timestamp: string;
  serverName: string;
  toolName: string;
  category: string;
  arguments: any;
  status: 'allow' | 'block' | 'pending';
  reason?: string;
  drift?: boolean;
  promptInjection?: boolean;
  isCategoryTransitionViolation?: boolean;
  sessionId?: string;
  evidence?: Evidence[];
  dataLabels?: DataLabel[];
  inspection?: InspectionSummary;
  intent?: string;
  destination?: string;
  approval?: {
    actionFingerprint: string;
    requestedAt: string;
    expiresAt: string;
    userResponse?: 'approve_once' | 'deny' | 'expired' | 'invalid';
  };
}

export interface GuardianConfig {
  servers: DownstreamServerConfig[];
  forbiddenTransitions: [string, string][];
  geminiApiKey?: string;
  autoApproveSafe: boolean;
  resourceLimits?: Partial<ResourceLimits>;
  firstSeenPolicy?: 'approve-safe' | 'require-approval' | 'block';
  sessionPolicy?: SessionPolicy;
}

// WebSocket Message Types
export type ExtensionMessage =
  | { type: 'approve_response'; id: string; actionFingerprint: string; approved: boolean }
  | { type: 'update_config'; config: GuardianConfig }
  | { type: 'approve_drift'; serverName: string; toolName: string; newHash: string }
  | { type: 'set_category'; serverName: string; toolName: string; category: string }
  | { type: 'request_state' }
  | { type: 'clear_logs' };

export type ProxyMessage =
  | { type: 'proxy_started'; pid: number; port: number }
  | { type: 'downstream_status'; serverName: string; status: 'connected' | 'disconnected' | 'error'; error?: string }
  | { type: 'log'; log: AuditLog }
  | { type: 'approve_request'; approval: ApprovalRequestView; driftDetails?: { oldHash?: string; newHash: string } }
  | { type: 'sync_state'; baselines: Record<string, Record<string, ToolBaseline>>; logs: AuditLog[]; config: GuardianConfig };
