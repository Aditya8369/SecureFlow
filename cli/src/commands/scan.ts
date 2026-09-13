import { NetworkUnavailableError, requestAiScan, fetchPolicySchemas, type AiScanRequest } from "../lib/api-client.js";
import { writeCache, type CachedPolicy } from "../lib/policy-cache.js";
import { runOfflineScan } from "../lib/offline-scanner.js";

export interface ScanCommandOptions {
  diff: string;
  apiKey: string;
  repoFullName?: string;
}

/**
 * Command handler for `secureflow scan`. Tries the full AI-powered scan
 * first (parity with the GitHub App). If the network is unavailable --
 * e.g. mid pre-commit hook with no connection -- it transparently falls
 * back to the cached-policy offline scanner instead of failing the hook
 * outright.
 *
 * VERIFY: wire this handler into your actual CLI entrypoint's command
 * parser (e.g. `cli/src/index.ts`), which wasn't reachable to inspect.
 * A typical commander.js registration looks like:
 *
 *   program
 *     .command("scan")
 *     .description("Run a SecureFlow security scan on staged changes")
 *     .action(() => runScanCommand({ diff: getStagedDiff(), apiKey: loadApiKey() }));
 */
export async function runScanCommand(options: ScanCommandOptions) {
  // Opportunistically refresh the policy cache in the background so the
  // offline fallback stays reasonably current even on happy-path runs.
  fetchPolicySchemas(options.apiKey)
    .then((schemas) => writeCache(schemas as CachedPolicy[]))
    .catch(() => {
      /* best-effort only -- offline path already tolerates a stale cache */
    });

    try {
    const request: AiScanRequest = {
      diff: options.diff,
      activePolicyIds: [],
    };

    if (options.repoFullName !== undefined) {
      request.repoFullName = options.repoFullName;
    }

    const result = await requestAiScan(request, options.apiKey);
    return { ...result, degraded: false };
  } catch (err) {
    if (err instanceof NetworkUnavailableError) {
      console.warn(
        "SecureFlow: no connection to the AI scanning service -- running a reduced, cached-policy scan instead.",
      );
      const offline = runOfflineScan(options.diff);
      return { ...offline, degraded: true };
    }
    throw err;
  }
}
