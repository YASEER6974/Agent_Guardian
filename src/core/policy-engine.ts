import * as crypto from 'crypto';
import { Decision, DecisionOutcome, Evidence, GuardianSession, PolicyOptions, SecurityEvent } from './types';

const BLOCK_RULES = new Set(['R1', 'R5', 'R7', 'B1', 'B2', 'B3']);
const ASK_RULES = new Set(['R2', 'R3', 'R4', 'R6', 'R8']);

export class PolicyEngine {
  private readonly strictUnknownTools: boolean;
  private readonly approvalTtlMs: number;

  constructor(options: PolicyOptions = {}) {
    this.strictUnknownTools = options.strictUnknownTools ?? false;
    this.approvalTtlMs = options.approvalTtlMs ?? 30_000;
  }

  evaluate(session: GuardianSession, event: SecurityEvent, evidence: Evidence[]): Decision {
    const started = performance.now();
    const matchedRuleIds = Array.from(new Set(evidence.map(item => item.ruleId).filter((id): id is string => Boolean(id))));
    let outcome: DecisionOutcome = this.baseOutcome(matchedRuleIds, evidence);

    if (matchedRuleIds.includes('R9')) {
      outcome = outcome === 'ALLOW' ? 'ASK' : outcome === 'ASK' ? 'BLOCK' : 'BLOCK';
    }

    const createdAt = new Date();
    const decision: Decision = {
      id: crypto.randomUUID(),
      sessionId: session.id,
      eventId: event.id,
      outcome,
      policyId: 'guardian-default-v1',
      matchedRuleIds,
      evidence: [...evidence],
      explanation: explain(outcome, matchedRuleIds, evidence),
      createdAt: createdAt.toISOString(),
      latencyMs: performance.now() - started
    };

    if (outcome === 'ASK') {
      decision.expiresAt = new Date(createdAt.getTime() + this.approvalTtlMs).toISOString();
    }
    return decision;
  }

  private baseOutcome(ruleIds: string[], evidence: Evidence[]): DecisionOutcome {
    if (ruleIds.some(id => BLOCK_RULES.has(id))) return 'BLOCK';
    if (ruleIds.includes('R4') && evidence.some(item => item.ruleId === 'R4' && item.metadata?.dataLabel === 'credential')) {
      return 'BLOCK';
    }
    if (this.strictUnknownTools && ruleIds.includes('R2')) return 'BLOCK';
    if (ruleIds.some(id => ASK_RULES.has(id))) return 'ASK';
    return 'ALLOW';
  }
}

function explain(outcome: DecisionOutcome, ruleIds: string[], evidence: Evidence[]): string {
  if (ruleIds.length === 0) return 'Allowed: no security policy rule was triggered.';
  const messages = evidence.map(item => item.message).filter(Boolean);
  const summary = messages.length > 0 ? messages.join('; ') : `rules ${ruleIds.join(', ')} triggered`;
  if (outcome === 'BLOCK') return `Blocked by policy: ${summary}`;
  if (outcome === 'ASK') return `Approval required: ${summary}`;
  return `Allowed with evidence: ${summary}`;
}
