/**
 * POST /api/cli/scan — AI-powered scan for the SecureFlow CLI.
 *
 * Auth: a single shared secret (`SECUREFLOW_API_KEY`), checked with
 * `crypto.timingSafeEqual` — the same style already used for
 * `GITHUB_WEBHOOK_SECRET` on the GitHub webhook route. This is
 * intentionally NOT per-user API keys (no such infrastructure exists
 * in this repo yet — see docs/api.md); that's tracked as a follow-up.
 */

import { timingSafeEqual } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { withErrorHandler, AppError } from "@/lib/middleware/error-handler";
import { withRateLimit } from "@/lib/middleware/rate-limit";

interface CliScanFile {
  path: string;
  content: string;
}

function isAuthorized(req: NextRequest): boolean {
  const secret = process.env.SECUREFLOW_API_KEY;
  if (!secret) return false;

  const authHeader = req.headers.get("authorization");
  const provided = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!provided) return false;

  const expected = Buffer.from(secret);
  const actual = Buffer.from(provided);
  if (expected.length !== actual.length) return false;

  return timingSafeEqual(expected, actual);
}

const handler = withErrorHandler(async function POST(req: NextRequest) {
  if (!isAuthorized(req)) {
    throw new AppError("Unauthorized", 401);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new AppError("Request body is not valid JSON", 400);
  }

  const { files } = body as { files?: CliScanFile[] };
  if (!Array.isArray(files) || files.length === 0) {
    throw new AppError('"files" must be a non-empty array', 400);
  }

  // TODO: replace with the real AI scan call.
  const findings = await runAiScan(files);

  return NextResponse.json({ findings }, { headers: { "Cache-Control": "no-store" } });
});

export const POST = withRateLimit(handler, {
  limit: 20,
  windowSeconds: 60,
  keyPrefix: "cli:scan",
});

export const dynamic = "force-dynamic";

// TODO: wire to the shared scan pipeline instead of stubbing.
async function runAiScan(files: CliScanFile[]): Promise<unknown[]> {
  throw new Error("runAiScan is not implemented yet");
}
