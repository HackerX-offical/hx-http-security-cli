import { checkReferrerPolicy } from '../../src/headers/rules/referrer.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkReferrerPolicy', () => {
  it('reports missing Referrer-Policy', () => {
    expect(checkReferrerPolicy(mockHeaders({}))[0].id).toBe('missing-referrer');
  });

  it('passes when set', () => {
    expect(
      checkReferrerPolicy(
        mockHeaders({ 'referrer-policy': 'strict-origin-when-cross-origin' }),
      ),
    ).toHaveLength(0);
  });
});
