import type { HeaderFinding } from '../types.js';
import { getHeader } from '../utils.js';

export function checkPermissionsPolicy(headers: Headers): HeaderFinding[] {
  const permissions = getHeader(headers, 'permissions-policy');
  if (!permissions) {
    return [
      {
        id: 'missing-permissions',
        severity: 'info',
        header: 'Permissions-Policy',
        message: 'Permissions-Policy not set (optional hardening).',
        present: false,
      },
    ];
  }
  return [];
}
