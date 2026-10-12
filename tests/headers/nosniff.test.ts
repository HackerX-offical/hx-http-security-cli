import { checkNoSniff } from '../../src/headers/rules/nosniff.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkNoSniff', () => {
  it('reports missing or wrong value', () => {
    expect(checkNoSniff(mockHeaders({}))[0].id).toBe('missing-nosniff');
    expect(checkNoSniff(mockHeaders({ 'x-content-type-options': 'foo' }))[0].id).toBe(
      'missing-nosniff',
    );
  });

  it('passes with nosniff', () => {
    expect(checkNoSniff(mockHeaders({ 'x-content-type-options': 'nosniff' }))).toHaveLength(
      0,
    );
  });
});
