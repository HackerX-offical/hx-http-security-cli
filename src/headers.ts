export interface HeaderFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  header: string;
  message: string;
  present: boolean;
}

export interface HeaderAuditResult {
  url: string;
  status: number;
  findings: HeaderFinding[];
  score: number;
  raw: Record<string, string>;
}

function getHeader(headers: Headers, name: string): string | undefined {
  return headers.get(name) ?? headers.get(name.toLowerCase()) ?? undefined;
}

function parseMaxAge(hsts: string): number | null {
  const match = /max-age=(\d+)/i.exec(hsts);
  return match ? Number(match[1]) : null;
}

export function auditSecurityHeaders(
  url: string,
  status: number,
  headers: Headers,
): HeaderAuditResult {
  const raw: Record<string, string> = {};
  headers.forEach((value, key) => {
    raw[key.toLowerCase()] = value;
  });

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
  } else {
    const maxAge = parseMaxAge(hsts);
    if (maxAge !== null && maxAge < 15552000) {
      findings.push({
        id: 'weak-hsts',
        severity: 'medium',
        header: 'Strict-Transport-Security',
        message: `HSTS max-age ${maxAge}s is below recommended 180 days.`,
        present: true,
      });
    }
  }

  const csp = getHeader(headers, 'content-security-policy');
  if (!csp) {
    findings.push({
      id: 'missing-csp',
      severity: 'medium',
      header: 'Content-Security-Policy',
      message: 'No CSP — XSS impact is harder to contain.',
      present: false,
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
    findings.push({
      id: 'weak-csp',
      severity: 'low',
      header: 'Content-Security-Policy',
      message: 'CSP allows unsafe-inline or unsafe-eval.',
      present: true,
    });
  }

  const xfo = getHeader(headers, 'x-frame-options');
  const frameAncestors = csp?.includes('frame-ancestors');
  if (!xfo && !frameAncestors) {
    findings.push({
      id: 'missing-clickjack',
      severity: 'medium',
      header: 'X-Frame-Options / CSP frame-ancestors',
      message: 'No clickjacking protection detected.',
      present: false,
    });
  }

  const xcto = getHeader(headers, 'x-content-type-options');
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    findings.push({
      id: 'missing-nosniff',
      severity: 'low',
      header: 'X-Content-Type-Options',
      message: 'nosniff not set — MIME sniffing risk.',
      present: false,
    });
  }

  const referrer = getHeader(headers, 'referrer-policy');
  if (!referrer) {
    findings.push({
      id: 'missing-referrer',
      severity: 'low',
      header: 'Referrer-Policy',
      message: 'Referrer-Policy not set.',
      present: false,
    });
  }

  const permissions = getHeader(headers, 'permissions-policy');
  if (!permissions) {
    findings.push({
      id: 'missing-permissions',
      severity: 'info',
      header: 'Permissions-Policy',
      message: 'Permissions-Policy not set (optional hardening).',
      present: false,
    });
  }

  const server = getHeader(headers, 'server');
  if (server) {
    findings.push({
      id: 'info-server',
      severity: 'info',
      header: 'Server',
      message: `Server banner exposed: ${server.slice(0, 80)}`,
      present: true,
    });
  }

  const xPowered = getHeader(headers, 'x-powered-by');
  if (xPowered) {
    findings.push({
      id: 'info-powered-by',
      severity: 'info',
      header: 'X-Powered-By',
      message: `Technology leak: ${xPowered.slice(0, 80)}`,
      present: true,
    });
  }

  const weights = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
  const penalty = findings.reduce((sum, f) => sum + weights[f.severity], 0);
  const score = Math.max(0, 100 - penalty);

  return { url, status, findings, score, raw };
}
