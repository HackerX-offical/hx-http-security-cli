import { checkDisclosureHeaders } from '../../src/headers/rules/disclosure.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkDisclosureHeaders', () => {
  it('returns empty when no disclosure headers', () => {
    expect(checkDisclosureHeaders(mockHeaders({}))).toHaveLength(0);
  });

  it('flags Server banner', () => {
    const findings = checkDisclosureHeaders(mockHeaders({ server: 'nginx/1.24' }));
    expect(findings.some((f) => f.id === 'info-server')).toBe(true);
  });

  it('flags X-Powered-By', () => {
    const findings = checkDisclosureHeaders(mockHeaders({ 'x-powered-by': 'Express' }));
    expect(findings.some((f) => f.id === 'info-powered-by')).toBe(true);
  });
});
