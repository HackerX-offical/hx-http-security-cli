import type { HeaderFinding } from '../types.js';
import { getHeader } from '../utils.js';

export function checkNoSniff(headers: Headers): HeaderFinding[] {
  const xcto = getHeader(headers, 'x-content-type-options');
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    return [
      {
        id: 'missing-nosniff',
        severity: 'low',
        header: 'X-Content-Type-Options',
        message: 'nosniff not set — MIME sniffing risk.',
        present: false,
      },
    ];
  }
  return [];
}
