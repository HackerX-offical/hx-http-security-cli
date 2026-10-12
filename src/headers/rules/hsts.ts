import type { HeaderFinding } from '../types.js';
import { getHeader, parseMaxAge } from '../utils.js';

const RECOMMENDED_MAX_AGE_SECONDS = 15552000; // 180 days

export function checkHsts(headers: Headers): HeaderFinding[] {
  const findings: HeaderFinding[] = [];
  const hsts = getHeader(headers, 'strict-transport-security');

  if (!hsts) {
    findings.push({
      id: 'missing-hsts',
      severity: 'high',
      header: 'Strict-Transport-Security',
      message: 'HSTS not set — browsers may downgrade to HTTP on first visit.',
      present: false,
    });
    return findings;
  }

  const maxAge = parseMaxAge(hsts);
  if (maxAge !== null && maxAge < RECOMMENDED_MAX_AGE_SECONDS) {
    findings.push({
      id: 'weak-hsts',
      severity: 'medium',
      header: 'Strict-Transport-Security',
      message: `HSTS max-age ${maxAge}s is below recommended 180 days.`,
      present: true,
    });
  }

  return findings;
}
