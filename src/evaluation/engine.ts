import * as crypto from 'crypto';
import { performance } from 'perf_hooks';
import { BrowserGuardian } from '../browser/guardian';
import { CrossSurfaceStore } from '../browser/cross-surface-store';
import { PolicyEngine } from '../core/policy-engine';
import { Evidence, GuardianLane, GuardianSession, SecurityEvent } from '../core/types';
import { checkTransition } from '../detector';
import { classifyText } from '../security/data-flow';
import { inspectStructuredText } from '../security/text-inspection';
import { diffToolDefinitions, fingerprintTool, snapshotTool } from '../security/tool-integrity';
import { EvaluationConfiguration, EvaluationLayer, EvaluationScenario, ScenarioResult } from './types';

export class EvaluationEngine {
  private readonly policy = new PolicyEngine();

  constructor(private readonly storagePath: string) {}

  evaluate(scenario: EvaluationScenario, configuration: EvaluationConfiguration, repetition = 0): ScenarioResult {
    const memoryBefore = process.memoryUsage().heapUsed;
    const started = performance.now();
    try {
      const evidence = this.collectEvidence(scenario, configuration, repetition);
      const event = securityEvent(scenario, repetition);
      const session = sessionFor(scenario, event);
      const decision = this.policy.evaluate(session, event, evidence);
      const overridden = decision.outcome === 'ASK' && scenario.input.simulateApproval === true;
      const detected = decision.outcome !== 'ALLOW';
      return {
        scenarioId: scenario.id,
        configurationId: configuration.id,
        split: scenario.split,
        lane: scenario.lane,
        malicious: scenario.malicious,
        expectedOutcome: scenario.expected.fullOutcome,
        outcome: decision.outcome,
        detected,
        attackSucceeded: scenario.malicious && (decision.outcome === 'ALLOW' || overridden),
        partialInfluence: scenario.malicious && scenario.expected.partialInfluence === true,
        permissionRequested: decision.outcome === 'ASK',
        overridden,
        matchedRuleIds: decision.matchedRuleIds,
        evidence,
        latencyMs: performance.now() - started,
        memoryDeltaBytes: process.memoryUsage().heapUsed - memoryBefore
      };
    } catch (error) {
      return {
        scenarioId: scenario.id,
        configurationId: configuration.id,
        split: scenario.split,
        lane: scenario.lane,
        malicious: scenario.malicious,
        expectedOutcome: scenario.expected.fullOutcome,
        outcome: 'BLOCK',
        detected: true,
        attackSucceeded: false,
        partialInfluence: scenario.expected.partialInfluence === true,
        permissionRequested: false,
        overridden: false,
        matchedRuleIds: [],
        evidence: [],
        latencyMs: performance.now() - started,
        memoryDeltaBytes: process.memoryUsage().heapUsed - memoryBefore,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private collectEvidence(
    scenario: EvaluationScenario,
    configuration: EvaluationConfiguration,
    repetition: number
  ): Evidence[] {
    if (!laneEnabled(configuration, scenario.lane)) return [];
    const eventId = `evaluation:${scenario.id}:${configuration.id}:${repetition}`;
    switch (scenario.kind) {
      case 'text':
        return this.textEvidence(scenario, configuration, eventId);
      case 'tool_drift':
        return enabled(configuration, 'integrity') ? driftEvidence(scenario, eventId) : [];
      case 'unknown_tool':
        return enabled(configuration, 'integrity')
          ? [finding('evaluation.integrity', 'R2', 'high', String(scenario.input.message || 'Unknown or shadowed tool'), eventId)]
          : [];
      case 'behavior_chain':
        return this.behaviorEvidence(scenario, configuration, eventId);
      case 'intent_scope':
        if (!enabled(configuration, 'intent')) return [];
        const allowed = (scenario.input.allowedCapabilities as string[] | undefined) || [];
        const requested = String(scenario.input.requestedCapability || '');
        return allowed.length > 0 && !allowed.includes(requested)
          ? [finding('evaluation.intent', 'R3', 'high', 'Requested capability is outside declared intent', eventId)]
          : [];
      case 'data_flow':
        return this.dataFlowEvidence(scenario, configuration, eventId);
      case 'browser_action':
        return this.browserEvidence(scenario, configuration, repetition);
      case 'cross_surface':
        return this.crossSurfaceEvidence(scenario, configuration, eventId);
      case 'benign':
        return [];
    }
  }

  private textEvidence(scenario: EvaluationScenario, configuration: EvaluationConfiguration, eventId: string): Evidence[] {
    if (!enabled(configuration, 'semantic')) return [];
    const inspected = inspectStructuredText(scenario.input.content, 'evaluation.text', eventId);
    return inspected.evidence.map(item => item.ruleId ? item : {
      ...item,
      ruleId: scenario.lane === 'mcp' ? 'R3' : 'R6'
    });
  }

  private behaviorEvidence(
    scenario: EvaluationScenario,
    configuration: EvaluationConfiguration,
    eventId: string
  ): Evidence[] {
    if (!enabled(configuration, 'behavior')) return [];
    const previous = String(scenario.input.previous || '');
    const current = String(scenario.input.current || '');
    const forbidden = [[previous, current]] as [string, string][];
    if (!checkTransition(previous, current, forbidden)) return [];
    const ruleId = String(scenario.input.ruleId || (current === 'EXECUTE_SYSTEM' ? 'R7' : 'R6'));
    return [finding('evaluation.behavior', ruleId, ruleId === 'R7' ? 'critical' : 'high',
      `Forbidden transition: ${previous} -> ${current}`, eventId)];
  }

  private dataFlowEvidence(
    scenario: EvaluationScenario,
    configuration: EvaluationConfiguration,
    eventId: string
  ): Evidence[] {
    if (!enabled(configuration, 'provenance')) return [];
    const text = JSON.stringify(scenario.input.sourceValue || '');
    const labels = classifyText(text);
    if (labels.includes('credential')) {
      return [finding('evaluation.data-flow', 'R5', 'critical', 'Credential data flows to a remote write', eventId, {
        dataLabel: 'credential'
      })];
    }
    if (labels.some(label => ['sensitive', 'personal', 'financial'].includes(label))) {
      return [finding('evaluation.data-flow', 'R4', 'high', 'Sensitive data flows to an untrusted destination', eventId, {
        dataLabel: labels.includes('financial') ? 'financial' : 'sensitive'
      })];
    }
    return [];
  }

  private browserEvidence(
    scenario: EvaluationScenario,
    configuration: EvaluationConfiguration,
    repetition: number
  ): Evidence[] {
    if (!enabled(configuration, 'semantic') && !enabled(configuration, 'provenance') && !enabled(configuration, 'intent')) {
      return [];
    }
    const sessionId = `${scenario.id}-${configuration.id}-${repetition}`;
    const guardian = new BrowserGuardian(new CrossSurfaceStore(this.storagePath), {
      trustedOrigins: (scenario.input.trustedOrigins as string[] | undefined) || []
    });
    const observation = guardian.observe({
      sessionId,
      url: String(scenario.input.url || 'https://example.invalid'),
      origin: String(scenario.input.origin || 'https://example.invalid'),
      visibleText: String(scenario.input.visibleText || ''),
      agentText: String(scenario.input.agentText || scenario.input.visibleText || '')
    });
    const action = guardian.gate({
      sessionId,
      type: (scenario.input.actionType || 'submit_form') as any,
      destination: String(scenario.input.destination || ''),
      payload: scenario.input.payload || {},
      dataLabels: (scenario.input.dataLabels as any) || []
    });
    return [
      ...observation.evidence.filter(item =>
        (item.detectorId === 'browser.content' && enabled(configuration, 'semantic')) ||
        (item.detectorId !== 'browser.content' && enabled(configuration, 'provenance'))
      ).map(item => {
        // This evaluator replays the frozen v1 research policy (ASK on text
        // suspicion). Live Browser MCP now uses B1/B2 hard content-release gates;
        // dedicated Chromium/MCP tests verify that newer boundary separately.
        return item.ruleId === 'B1' ? { ...item, ruleId: 'R6' } : item;
      }),
      ...action.evidence.filter(item => {
        if (item.detectorId === 'browser.session-policy') return enabled(configuration, 'intent');
        return enabled(configuration, 'provenance');
      })
    ];
  }

  private crossSurfaceEvidence(
    scenario: EvaluationScenario,
    configuration: EvaluationConfiguration,
    eventId: string
  ): Evidence[] {
    if (!enabled(configuration, 'provenance') || !configuration.lanes.mcp || !configuration.lanes.browser || scenario.input.trusted === true) return [];
    const category = String(scenario.input.category || 'WRITE_COMMUNICATION');
    const ruleId = category === 'EXECUTE_SYSTEM' ? 'R7' : 'R8';
    return [finding('evaluation.cross-surface', ruleId, ruleId === 'R7' ? 'critical' : 'high',
      `Untrusted browser content influenced MCP ${category}`, eventId, {
        match: scenario.input.match || 'coarse-session-taint'
      })];
  }
}

function driftEvidence(scenario: EvaluationScenario, eventId: string): Evidence[] {
  const trusted = snapshotTool(scenario.input.trustedTool || {});
  const observed = snapshotTool(scenario.input.observedTool || {});
  if (fingerprintTool(trusted) === fingerprintTool(observed)) return [];
  const diff = diffToolDefinitions(trusted, observed);
  return [finding('evaluation.tool-integrity', 'R1', 'critical', 'Tool definition drifted from trusted baseline', eventId, {
    differences: diff.differences
  })];
}

function securityEvent(scenario: EvaluationScenario, repetition: number): SecurityEvent {
  return {
    id: `event:${scenario.id}:${repetition}`,
    sessionId: `session:${scenario.id}:${repetition}`,
    timestamp: new Date(0).toISOString(),
    lane: lane(scenario.lane),
    kind: scenario.kind,
    operation: scenario.title,
    dataLabels: []
  };
}

function sessionFor(scenario: EvaluationScenario, event: SecurityEvent): GuardianSession {
  return {
    id: event.sessionId,
    intent: String(scenario.input.intent || ''),
    allowedCapabilities: (scenario.input.allowedCapabilities as string[] | undefined) || [],
    trustedDestinations: (scenario.input.trustedDestinations as string[] | undefined) || [],
    startedAt: event.timestamp,
    events: [event],
    dataFlow: [],
    taint: []
  };
}

function finding(
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
    detectorVersion: 'evaluation-v1',
    ruleId,
    severity,
    confidence: 1,
    message,
    eventIds: [eventId],
    provenance: { lane: 'system' },
    metadata
  };
}

function enabled(configuration: EvaluationConfiguration, layer: EvaluationLayer): boolean {
  return configuration.layers[layer];
}

function laneEnabled(configuration: EvaluationConfiguration, scenarioLane: EvaluationScenario['lane']): boolean {
  if (scenarioLane === 'mcp') return configuration.lanes.mcp;
  if (scenarioLane === 'browser') return configuration.lanes.browser;
  return configuration.lanes.mcp && configuration.lanes.browser;
}

function lane(value: EvaluationScenario['lane']): GuardianLane {
  return value === 'cross' ? 'system' : value;
}
