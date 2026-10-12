import { auditSecurityHeaders } from '../src/headers.js';

function mockHeaders(map: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(map)) {
    h.set(k, v);
  }
  return h;
}

describe('auditSecurityHeaders', () => {
  it('flags missing HSTS and CSP', () => {
    const result = auditSecurityHeaders(
      'https://example.com',
      200,
      mockHeaders({ 'x-content-type-options': 'nosniff' }),
    );
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('missing-hsts');
    expect(ids).toContain('missing-csp');
    expect(result.score).toBeLessThan(100);
  });

  it('scores strong configuration higher', () => {
    const result = auditSecurityHeaders(
      'https://example.com',
      200,
      mockHeaders({
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
      }),
    );
    expect(result.score).toBeGreaterThanOrEqual(90);
  });
});
