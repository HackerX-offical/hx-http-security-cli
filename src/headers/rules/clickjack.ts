import type { HeaderFinding } from '../types.js';
import { getHeader } from '../utils.js';
import { getCspValue } from './csp.js';

export function checkClickjack(headers: Headers): HeaderFinding[] {
  const xfo = getHeader(headers, 'x-frame-options');
  const csp = getCspValue(headers);
  const frameAncestors = csp?.includes('frame-ancestors');

  if (!xfo && !frameAncestors) {
    return [
      {
        id: 'missing-clickjack',
        severity: 'medium',
        header: 'X-Frame-Options / CSP frame-ancestors',
        message: 'No clickjacking protection detected.',
        present: false,
      },
    ];
  }

  return [];
}
