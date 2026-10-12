import type { HeaderAuditResult } from './types.js';
import { computeScore } from './scoring.js';
import { headersToRaw } from './utils.js';
import {
  checkClickjack,
  checkCsp,
  checkDisclosureHeaders,
  checkHsts,
  checkNoSniff,
  checkPermissionsPolicy,
  checkReferrerPolicy,
} from './rules/index.js';

export function auditSecurityHeaders(
  url: string,
  status: number,
  headers: Headers,
): HeaderAuditResult {
  const raw = headersToRaw(headers);

  const findings = [
    ...checkHsts(headers),
    ...checkCsp(headers),
    ...checkClickjack(headers),
    ...checkNoSniff(headers),
    ...checkReferrerPolicy(headers),
    ...checkPermissionsPolicy(headers),
    ...checkDisclosureHeaders(headers),
  ];

  const score = computeScore(findings);

  return { url, status, findings, score, raw };
}
