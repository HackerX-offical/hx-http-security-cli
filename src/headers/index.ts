export type { HeaderAuditResult, HeaderFinding, HeaderSeverity } from './types.js';
export { auditSecurityHeaders } from './audit.js';
export { computeScore, penaltyForFindings, SEVERITY_WEIGHTS } from './scoring.js';
export { getHeader, headersToRaw, parseMaxAge } from './utils.js';
export * from './rules/index.js';
