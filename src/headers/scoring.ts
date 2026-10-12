import type { HeaderFinding, HeaderSeverity } from './types.js';

export const SEVERITY_WEIGHTS: Record<HeaderSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export function penaltyForFindings(findings: HeaderFinding[]): number {
  return findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
}

export function computeScore(findings: HeaderFinding[]): number {
  const penalty = penaltyForFindings(findings);
  return Math.max(0, 100 - penalty);
}
