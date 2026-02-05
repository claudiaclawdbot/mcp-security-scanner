/**
 * Risk scoring algorithm
 */

const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 10,
  medium: 3,
  low: 1,
  info: 0
};

export function calculateRiskScore(findings) {
  let score = 0;
  for (const f of findings) {
    score += SEVERITY_WEIGHTS[f.severity] || 0;
  }
  return Math.min(score, 100);
}

export function getRiskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}
