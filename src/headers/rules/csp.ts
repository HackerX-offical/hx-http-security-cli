import type { HeaderFinding } from '../types.js';
import { getHeader } from '../utils.js';

export function getCspValue(headers: Headers): string | undefined {
  return getHeader(headers, 'content-security-policy');
}

export function checkCsp(headers: Headers): HeaderFinding[] {
  const findings: HeaderFinding[] = [];
  const csp = getCspValue(headers);

  if (!csp) {
    findings.push({
      id: 'missing-csp',
      severity: 'medium',
      header: 'Content-Security-Policy',
      message: 'No CSP — XSS impact is harder to contain.',
      present: false,
    });
    return findings;
  }

  if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
    findings.push({
      id: 'weak-csp',
      severity: 'low',
      header: 'Content-Security-Policy',
      message: 'CSP allows unsafe-inline or unsafe-eval.',
      present: true,
    });
  }

  return findings;
}
