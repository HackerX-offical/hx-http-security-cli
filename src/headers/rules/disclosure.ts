import type { HeaderFinding } from '../types.js';
import { getHeader } from '../utils.js';

const BANNER_MAX_LEN = 80;

export function checkDisclosureHeaders(headers: Headers): HeaderFinding[] {
  const findings: HeaderFinding[] = [];

  const server = getHeader(headers, 'server');
  if (server) {
    findings.push({
      id: 'info-server',
      severity: 'info',
      header: 'Server',
      message: `Server banner exposed: ${server.slice(0, BANNER_MAX_LEN)}`,
      present: true,
    });
  }

  const xPowered = getHeader(headers, 'x-powered-by');
  if (xPowered) {
    findings.push({
      id: 'info-powered-by',
      severity: 'info',
      header: 'X-Powered-By',
      message: `Technology leak: ${xPowered.slice(0, BANNER_MAX_LEN)}`,
      present: true,
    });
  }

  return findings;
}
