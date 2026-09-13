/**
 * Thin client for the same AI-powered scanning endpoints the SecureFlow
 * GitHub App uses (see docs/api.md). Used by `commands/scan.ts` so the
 * CLI gets full parity with the app's AI review instead of a separate,
 * weaker code path.
 */

export interface AiScanRequest {
  diff: string;
  repoFullName?: string;
  activePolicyIds: string[];
}

export interface AiScanFinding {
  type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  file: string;
  line?: number;
  description: string;
  remediation: string[];
}

export interface AiScanResponse {
  findings: AiScanFinding[];
  source: "ai";
}

export class NetworkUnavailableError extends Error {
  constructor(cause?: unknown) {
    super("SecureFlow API unreachable");
    this.name = "NetworkUnavailableError";
    this.cause = cause;
  }
}

const DEFAULT_TIMEOUT_MS = 4_000;
const DEFAULT_BASE_URL = process.env.SECUREFLOW_API_URL ?? "https://secure-flow-six.vercel.app";

/**
 * Calls the hosted AI scan endpoint. Fails fast (short timeout) so a
 * pre-commit hook never hangs on a bad connection -- callers should catch
 * `NetworkUnavailableError` and fall back to `offline-scanner.ts`.
 */
export async function requestAiScan(
  req: AiScanRequest,
  apiKey: string,
  baseUrl: string = DEFAULT_BASE_URL,
): Promise<AiScanResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const res = await fetch(`${baseUrl}/api/cli/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(req),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`SecureFlow API responded with ${res.status}`);
    }

    const data = (await res.json()) as { findings: AiScanFinding[] };
    return { findings: data.findings, source: "ai" };
  } catch (err) {
    throw new NetworkUnavailableError(err);
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Pulls the latest policy schema definitions from the server so they can
 * be cached locally by `policy-cache.ts` for offline use.
 */
export async function fetchPolicySchemas(
  apiKey: string,
  baseUrl: string = DEFAULT_BASE_URL,
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const res = await fetch(`${baseUrl}/api/policies`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`Policy fetch failed with ${res.status}`);
    return await res.json();
  } catch (err) {
    throw new NetworkUnavailableError(err);
  } finally {
    clearTimeout(timeout);
  }
}
