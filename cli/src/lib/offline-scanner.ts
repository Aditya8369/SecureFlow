import type { AiScanFinding } from "./api-client.js";
import { getUsablePolicies, type CachedPolicy } from "./policy-cache.js";

/**
 * Regex-based local validator. This is intentionally simpler than the
 * Groq-backed ArmorIQScanner -- it exists only so a pre-commit hook
 * doesn't fail open (or hang) when the network is down. It re-uses the
 * cached policy definitions so the two code paths stay conceptually in
 * sync even though the offline path can't do LLM-level reasoning.
 */
export function runOfflineScan(diff: string): {
  findings: AiScanFinding[];
  source: "offline";
  policiesStale: boolean;
} {
  const { policies, stale } = getUsablePolicies();
  const findings: AiScanFinding[] = [];

  for (const policy of policies as CachedPolicy[]) {
    if (!policy.enabled) continue;

    let regex: RegExp;
    try {
      regex = new RegExp(policy.pattern, "gim");
    } catch {
      continue; // skip a malformed cached pattern rather than crash the hook
    }

    const lines = diff.split("\n");
    lines.forEach((line, idx) => {
      if (regex.test(line)) {
        findings.push({
          type: policy.id,
          severity: policy.severity,
          file: "staged-diff",
          line: idx + 1,
          description: `[offline] ${policy.name} matched on this line.`,
          remediation: [policy.remediation],
        });
      }
    });
  }

  return { findings, source: "offline", policiesStale: stale };
}
