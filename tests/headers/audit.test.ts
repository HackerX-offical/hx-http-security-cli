import { auditSecurityHeaders } from '../../src/headers/audit.js';
import { mockHeaders } from '../helpers/mock-headers.js';

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
    expect(result.raw['x-content-type-options']).toBe('nosniff');
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
