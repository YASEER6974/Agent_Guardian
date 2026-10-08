import * as crypto from 'crypto';
import { PolicyEngine } from '../core/policy-engine';
import { DataLabel, Decision, Evidence, GuardianSession, SecurityEvent } from '../core/types';
import { SessionPolicy } from '../types';
import { inspectStructuredText } from '../security/text-inspection';
import { CrossSurfaceStore, fingerprintsFor } from './cross-surface-store';

export interface BrowserObservation {
  sessionId: string;
  url: string;
  origin: string;
  title?: string;
  visibleText: string;
  agentText?: string;
  frames?: Array<{ url: string; visibleText: string }>;
  links?: Array<{ text: string; href: string }>;
  forms?: Array<{ action: string; method: string; fields: string[] }>;
  networkDestinations?: string[];
  inspectionComplete?: boolean;
}

export type BrowserActionType =
  | 'navigate'
  | 'fill'
  | 'submit_form'
  | 'download'
  | 'credential_entry'
  | 'purchase'
  | 'network_request'
  | 'execute_system';

export interface BrowserAction {
  sessionId: string;
  type: BrowserActionType;
  source?: string;
  destination?: string;
  payload?: unknown;
  dataLabels?: DataLabel[];
  capability?: string;
  denialReason?: string;
}

export interface BrowserGuardianOptions {
  trustedOrigins?: string[];
  sessionPolicy?: SessionPolicy;
  approvalTtlMs?: number;
  allowedOrigins?: string[];
}

export class BrowserGuardian {
  private readonly policyEngine: PolicyEngine;
  private readonly trustedOrigins: Set<string>;
  private readonly sessionPolicy: SessionPolicy;
  private readonly allowedOrigins?: Set<string>;

  constructor(private readonly store: CrossSurfaceStore, options: BrowserGuardianOptions = {}) {
    this.policyEngine = new PolicyEngine({ approvalTtlMs: options.approvalTtlMs });
    this.trustedOrigins = new Set((options.trustedOrigins || []).map(normalizeOrigin));
    this.sessionPolicy = options.sessionPolicy || { intent: '', allowedCapabilities: [], trustedDestinations: [] };
    this.allowedOrigins = options.allowedOrigins ? new Set(options.allowedOrigins.map(normalizeOrigin)) : undefined;
  }

  observe(observation: BrowserObservation): { event: SecurityEvent; evidence: Evidence[]; decision: Decision } {
    const eventId = `browser-observation:${crypto.randomUUID()}`;
    const inspection = inspectStructuredText(observation, 'browser.content', eventId);
    const evidence: Evidence[] = inspection.evidence.map(item => ({
      ...item, ruleId: item.ruleId || 'B1', provenance: { ...item.provenance, lane: 'browser' }
    }));
    if (inspection.truncated || observation.inspectionComplete === false) {
      evidence.push(makeEvidence('browser.inspection', 'B2', 'high',
        'Page inspection is incomplete; content is withheld', eventId));
    }
    const hidden = hiddenAgentSegments(observation.visibleText, observation.agentText);
    if (hidden.length > 0) {
      evidence.push(makeEvidence('browser.visibility', 'R6', 'high',
        'Agent-ingested content contains text absent from the rendered page', eventId, {
          hiddenSegmentCount: hidden.length,
          samples: hidden.slice(0, 3).map(item => item.slice(0, 120))
        }));
    }
    const trusted = this.trustedOrigins.has(normalizeOrigin(observation.origin));
    const labels: DataLabel[] = trusted && evidence.length === 0 ? ['trusted'] : ['untrusted'];
    const event: SecurityEvent = {
      id: eventId,
      sessionId: observation.sessionId,
      timestamp: new Date().toISOString(),
      lane: 'browser',
      kind: 'observation',
      operation: 'page.observe',
      source: observation.url,
      dataLabels: labels,
      metadata: {
        origin: observation.origin,
        title: observation.title,
        trustedOrigin: trusted,
        stringsInspected: inspection.stringsInspected,
        inspectionTruncated: inspection.truncated,
        hiddenSegmentCount: hidden.length
      }
    };
    const decision = this.policyEngine.evaluate(sessionFor(observation.sessionId, this.sessionPolicy, event, labels), event, evidence);
    this.store.append({ event, evidence, fingerprints: fingerprintsFor(observation), decision });
    return { event, evidence, decision };
  }

  gate(action: BrowserAction): Decision {
    const eventId = `browser-action:${crypto.randomUUID()}`;
    const influence = this.store.matchBrowserInfluence(action.sessionId, action.payload);
    const labels = Array.from(new Set([...(action.dataLabels || []), ...influence.labels]));
    const event: SecurityEvent = {
      id: eventId,
      sessionId: action.sessionId,
      timestamp: new Date().toISOString(),
      lane: 'browser',
      kind: 'action',
      operation: action.type,
      capability: action.capability || capabilityFor(action.type),
      source: action.source,
      destination: action.destination,
      dataLabels: labels,
      input: action.payload
    };
    const evidence: Evidence[] = [];
    if (action.denialReason) {
      evidence.push(makeEvidence('browser.boundary', 'B3', 'high', action.denialReason, eventId));
    }
    const destinationDenied = Boolean(action.destination && this.allowedOrigins &&
      (!isWebUrl(action.destination) || !this.allowedOrigins.has(normalizeOrigin(action.destination))));
    if (destinationDenied) {
      evidence.push(makeEvidence('browser.destination', 'B3', 'critical',
        'Destination is outside the operator-configured browser origin allowlist', eventId));
    }
    const privileged = ['submit_form', 'download', 'credential_entry', 'purchase', 'network_request', 'execute_system'].includes(action.type);
    if (privileged && influence.influenced && influence.labels.includes('untrusted')) {
      evidence.push(makeEvidence('browser.provenance', action.type === 'execute_system' ? 'R7' : 'R6',
        action.type === 'execute_system' ? 'critical' : 'high',
        `Untrusted browser content influenced ${action.type}`, eventId, {
          match: influence.exact ? 'exact-fingerprint' : 'coarse-session-taint',
          sourceEventIds: influence.sourceEventIds
        }));
    }
    if (action.type === 'credential_entry' && !this.destinationTrusted(action.destination)) {
      evidence.push(makeEvidence('browser.destination', 'R4', 'critical',
        'Credential entry targets an untrusted destination', eventId, { dataLabel: 'credential' }));
    }
    const capability = event.capability || '';
    if (this.sessionPolicy.allowedCapabilities.length > 0 && !this.sessionPolicy.allowedCapabilities.includes(capability)) {
      evidence.push(makeEvidence('browser.session-policy', 'R3', 'high',
        `Capability ${capability} is outside the declared session policy`, eventId));
    }
    const session = sessionFor(action.sessionId, this.sessionPolicy, event, labels);
    const decision = this.policyEngine.evaluate(session, event, evidence);
    if (destinationDenied) {
      decision.outcome = 'BLOCK';
      decision.explanation = 'Blocked: destination is outside the operator-configured browser origin allowlist.';
      delete decision.expiresAt;
    }
    this.store.append({ event, evidence, fingerprints: fingerprintsFor(action.payload), decision });
    return decision;
  }

  private destinationTrusted(destination?: string): boolean {
    if (!destination) return false;
    const origin = normalizeOrigin(destination);
    return this.trustedOrigins.has(origin) || this.sessionPolicy.trustedDestinations.some(item => normalizeOrigin(item) === origin);
  }
}

function isWebUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
  } catch { return false; }
}

function capabilityFor(action: BrowserActionType): string {
  return `BROWSER_${action.toUpperCase()}`;
}

function hiddenAgentSegments(visibleText: string, agentText?: string): string[] {
  if (!agentText) return [];
  const visible = normalizeText(visibleText);
  const compactVisible = visible.replace(/\s/g, '');
  return agentText.split(/\r?\n/)
    .map(normalizeText)
    .filter(segment => segment.length >= 8 && !visible.includes(segment) && !compactVisible.includes(segment.replace(/\s/g, '')));
}

function normalizeText(value: string): string {
  return value.normalize('NFKC').replace(/\s+/g, ' ').trim().toLowerCase();
}

function normalizeOrigin(value: string): string {
  try { return new URL(value).origin.toLowerCase(); } catch { return value.trim().toLowerCase(); }
}

function sessionFor(
  id: string,
  policy: SessionPolicy,
  event: SecurityEvent,
  taint: DataLabel[]
): GuardianSession {
  return {
    id,
    intent: policy.intent,
    allowedCapabilities: policy.allowedCapabilities,
    trustedDestinations: policy.trustedDestinations,
    startedAt: event.timestamp,
    events: [event],
    dataFlow: [],
    taint
  };
}

function makeEvidence(
  detectorId: string,
  ruleId: string,
  severity: Evidence['severity'],
  message: string,
  eventId: string,
  metadata?: Record<string, unknown>
): Evidence {
  return {
    id: crypto.createHash('sha256').update(`${detectorId}\0${ruleId}\0${eventId}\0${message}`).digest('hex'),
    detectorId,
    detectorVersion: '1.0.0',
    ruleId,
    severity,
    confidence: 1,
    message,
    eventIds: [eventId],
    provenance: { lane: 'browser' },
    metadata
  };
}
