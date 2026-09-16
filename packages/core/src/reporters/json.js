export function toJsonReport(result, options = {}) {
  return JSON.stringify({
    schemaVersion: '0.1.0',
    generatedAt: result.scannedAt,
    product: result.product,
    posture: result.summary,
    filters: result.filters ?? null,
    findings: result.findings,
    preupdate: options.preupdate ?? null
  }, null, 2);
}
