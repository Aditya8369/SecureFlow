/**
 * Thin client for the AI-powered scanning endpoint the SecureFlow GitHub
 * App uses (see docs/api.md). Gives the CLI parity with the App's AI
 * review, on top of the always-available local scan in `scanner.ts`.
 */

export interface StagedFileForAiScan {
  path: string;
  content: string;
}

export interface AiFinding {
  path: string;
  line?: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  type: string;
  description: string;
  remediation: string[];
}

export class NetworkUnavailableError extends Error {
  constructor(cause?: unknown) {
    super("SecureFlow API unreachable");
    this.name = "NetworkUnavailableError";
    this.cause = cause;
  }
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_BASE_URL = process.env.SECUREFLOW_API_URL ?? "https://secure-flow-six.vercel.app";

/**
 * Sends staged file contents to the hosted AI scanner. Fails fast (short
 * timeout) and always throws `NetworkUnavailableError` on any failure so
 * callers can swallow it and fall back to the local-only scan --
 * never block a commit on connectivity.
 */
export async function requestAiFileScan(
  files: StagedFileForAiScan[],
  apiKey: string,
  baseUrl: string = DEFAULT_BASE_URL,
): Promise<AiFinding[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const res = await fetch(`${baseUrl}/api/cli/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ files }),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`SecureFlow API responded with ${res.status}`);
    }

    const data = (await res.json()) as { findings: AiFinding[] };
    return data.findings ?? [];
  } catch (err) {
    throw new NetworkUnavailableError(err);
  } finally {
    clearTimeout(timeout);
  }
}
