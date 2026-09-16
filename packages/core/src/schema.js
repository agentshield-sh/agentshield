export const severities = ['info', 'low', 'medium', 'high', 'critical'];
export const confidences = ['low', 'medium', 'high'];

export function createFinding(input) {
  return {
    id: input.id,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    title: input.title,
    description: input.description,
    path: input.path ?? null,
    recommendation: input.recommendation,
    metadata: input.metadata ?? {}
  };
}

export function summarizeFindings(findings) {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}
