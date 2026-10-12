import type { HeaderFinding } from '../types.js';
import { getHeader } from '../utils.js';

export function checkReferrerPolicy(headers: Headers): HeaderFinding[] {
  const referrer = getHeader(headers, 'referrer-policy');
  if (!referrer) {
    return [
      {
        id: 'missing-referrer',
        severity: 'low',
        header: 'Referrer-Policy',
        message: 'Referrer-Policy not set.',
        present: false,
      },
    ];
  }
  return [];
}
