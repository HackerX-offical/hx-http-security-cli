import { checkPermissionsPolicy } from '../../src/headers/rules/permissions.js';
import { mockHeaders } from '../helpers/mock-headers.js';

describe('checkPermissionsPolicy', () => {
  it('reports missing Permissions-Policy as info', () => {
    const findings = checkPermissionsPolicy(mockHeaders({}));
    expect(findings[0].id).toBe('missing-permissions');
    expect(findings[0].severity).toBe('info');
  });

  it('passes when set', () => {
    expect(
      checkPermissionsPolicy(mockHeaders({ 'permissions-policy': 'geolocation=()' })),
    ).toHaveLength(0);
  });
});
