export type HeaderSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface HeaderFinding {
  id: string;
  severity: HeaderSeverity;
  header: string;
  message: string;
  present: boolean;
}

export interface HeaderAuditResult {
  url: string;
  status: number;
  findings: HeaderFinding[];
  score: number;
  raw: Record<string, string>;
}
