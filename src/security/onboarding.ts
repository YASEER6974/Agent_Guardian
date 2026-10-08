import * as crypto from 'crypto';
import { CompletenessLedger } from '../core/completeness-ledger';
import { Evidence, InspectionSummary } from '../core/types';
import { DownstreamServerConfig } from '../types';
import { AcceptedRiskStore } from './accepted-risks';
import { inspectStructuredText } from './text-inspection';

export interface OnboardingResult {
  safe: boolean;
  evidence: Evidence[];
  suppressedEvidence: Evidence[];
  inspection: InspectionSummary;
}

export function inspectOnboarding(
  server: DownstreamServerConfig,
  tool: unknown,
  eventId: string,
  acceptedRisks: AcceptedRiskStore,
  maxStrings = 2_000
): OnboardingResult {
  const ledger = new CompletenessLedger();
  const configStarted = new Date().toISOString();
  const configInspection = inspectStructuredText(
    { name: server.name, type: server.type || (server.url ? 'http' : 'stdio'), url: server.url,
      command: server.command, args: server.args || [], envKeys: Object.keys(server.env || {}), headerKeys: Object.keys(server.headers || {}) },
    'onboarding.server-config',
    eventId,
    maxStrings
  );
  ledger.record({
    analyzerId: 'onboarding.server-config',
    subject: server.name,
    outcome: configInspection.truncated ? 'partial' : 'completed',
    startedAt: configStarted,
    finishedAt: new Date().toISOString(),
    reason: configInspection.truncated ? 'String inspection limit reached' : undefined,
    limits: { maxStrings },
    observed: { stringsInspected: configInspection.stringsInspected }
  });

  const toolStarted = new Date().toISOString();
  const toolInspection = inspectStructuredText(tool, 'onboarding.tool-definition', eventId, maxStrings);
  ledger.record({
    analyzerId: 'onboarding.tool-definition',
    subject: `${server.name}:tool-definition`,
    outcome: toolInspection.truncated ? 'partial' : 'completed',
    startedAt: toolStarted,
    finishedAt: new Date().toISOString(),
    reason: toolInspection.truncated ? 'String inspection limit reached' : undefined,
    limits: { maxStrings },
    observed: { stringsInspected: toolInspection.stringsInspected }
  });

  const allEvidence = [...configInspection.evidence, ...toolInspection.evidence];
  const suppressedEvidence = allEvidence.filter(finding => acceptedRisks.isAccepted(finding));
  const evidence = allEvidence.filter(finding => !acceptedRisks.isAccepted(finding));
  const inspection = ledger.summarize();
  const unsafeEvidence = evidence.some(finding => finding.severity === 'high' || finding.severity === 'critical');
  return {
    safe: inspection.complete && !unsafeEvidence,
    evidence,
    suppressedEvidence,
    inspection
  };
}

export function shadowingEvidence(toolName: string, serverNames: string[], eventId: string): Evidence {
  const sortedServers = [...serverNames].sort();
  const message = `Tool '${toolName}' is exposed by multiple servers: ${sortedServers.join(', ')}`;
  return {
    id: crypto.createHash('sha256').update(`shadowing\0${toolName}\0${sortedServers.join('\0')}`).digest('hex'),
    detectorId: 'mcp.tool-shadowing',
    detectorVersion: '1.0.0',
    ruleId: 'R2',
    severity: 'high',
    confidence: 1,
    message,
    eventIds: [eventId],
    provenance: { lane: 'mcp', source: sortedServers.join(',') },
    metadata: { code: 'TOOL_SHADOWING', toolName, serverNames: sortedServers }
  };
}
