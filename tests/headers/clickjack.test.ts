import { checkClickjack } from '../../src/headers/rules/clickjack.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkClickjack', () => {
  it('reports missing protection', () => {
    const findings = checkClickjack(mockHeaders({}));
    expect(findings[0].id).toBe('missing-clickjack');
  });

  it('passes with X-Frame-Options', () => {
    expect(checkClickjack(mockHeaders({ 'x-frame-options': 'DENY' }))).toHaveLength(0);
  });

  it('passes with CSP frame-ancestors', () => {
    expect(
      checkClickjack(
        mockHeaders({
          'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toHaveLength(0);
  });
});
