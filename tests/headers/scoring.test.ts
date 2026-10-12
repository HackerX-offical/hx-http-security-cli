import { computeScore, penaltyForFindings, SEVERITY_WEIGHTS } from '../../src/headers/scoring.js';
import type { HeaderFinding } from '../../src/headers/types.js';

function finding(severity: HeaderFinding['severity'], id = 'test'): HeaderFinding {
  return {
    id,
    severity,
    header: 'Test',
    message: 'test',
    present: false,
  };
}

describe('scoring', () => {
  it('applies severity weights', () => {
    expect(SEVERITY_WEIGHTS.high).toBe(15);
    expect(penaltyForFindings([finding('high'), finding('medium')])).toBe(15 + 8);
  });

  it('computes score with floor at 0', () => {
    const many: HeaderFinding[] = Array.from({ length: 10 }, (_, i) =>
      finding('critical', `c-${i}`),
    );
    expect(computeScore(many)).toBe(0);
  });

  it('returns 100 for no findings', () => {
    expect(computeScore([])).toBe(100);
  });

  it('info findings do not reduce score', () => {
    expect(computeScore([finding('info')])).toBe(100);
  });
});
