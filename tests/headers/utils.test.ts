import { getHeader, headersToRaw, parseMaxAge } from '../../src/headers/utils.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('header utils', () => {
  it('getHeader is case-insensitive via Headers API', () => {
    const h = mockHeaders({ 'X-Custom': 'value' });
    expect(getHeader(h, 'x-custom')).toBe('value');
  });

  it('parseMaxAge extracts seconds', () => {
    expect(parseMaxAge('max-age=31536000; includeSubDomains')).toBe(31536000);
    expect(parseMaxAge('invalid')).toBeNull();
  });

  it('headersToRaw lowercases keys', () => {
    const raw = headersToRaw(mockHeaders({ 'Content-Type': 'text/html' }));
    expect(raw['content-type']).toBe('text/html');
  });
});
