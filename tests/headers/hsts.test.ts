import { checkHsts } from '../../src/headers/rules/hsts.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkHsts', () => {
  it('reports missing HSTS', () => {
    const findings = checkHsts(mockHeaders({}));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('missing-hsts');
    expect(findings[0].severity).toBe('high');
  });

  it('accepts strong max-age', () => {
    const findings = checkHsts(
      mockHeaders({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
    );
    expect(findings).toHaveLength(0);
  });

  it('flags weak max-age', () => {
    const findings = checkHsts(mockHeaders({ 'strict-transport-security': 'max-age=86400' }));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('weak-hsts');
    expect(findings[0].severity).toBe('medium');
  });
});
