import { checkCsp } from '../../src/headers/rules/csp.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkCsp', () => {
  it('reports missing CSP', () => {
    const findings = checkCsp(mockHeaders({}));
    expect(findings[0].id).toBe('missing-csp');
    expect(findings[0].present).toBe(false);
  });

  it('passes strict CSP', () => {
    const findings = checkCsp(mockHeaders({ 'content-security-policy': "default-src 'self'" }));
    expect(findings).toHaveLength(0);
  });

  it('flags unsafe-inline', () => {
    const findings = checkCsp(
      mockHeaders({
        'content-security-policy': "default-src 'self' 'unsafe-inline'",
      }),
    );
    expect(findings[0].id).toBe('weak-csp');
  });

  it('flags unsafe-eval', () => {
    const findings = checkCsp(
      mockHeaders({
        'content-security-policy': "script-src 'unsafe-eval'",
      }),
    );
    expect(findings[0].id).toBe('weak-csp');
  });
});
