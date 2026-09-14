/**
 * POST /api/sbom/scan — Enqueue an asynchronous SBOM scan.
 *
 * Accepts manifest file contents (e.g. package.json or requirements.txt)
 * and enqueues a background job to BullMQ rather than performing CPU-heavy
 * dependency parsing and vulnerability matching inside the HTTP request.
 *
 * Returns immediately with HTTP 202 Accepted and a job handle that can
 * be polled at /api/sbom/scan/status/[jobId].
 */

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/auth";
import { withErrorHandler, AppError } from "@/lib/middleware/error-handler";
import { withRateLimit } from "@/lib/middleware/rate-limit";
import { enqueueSbomScan, MAX_SBOM_BYTES } from "@/lib/queue/sbomQueue";
import { z } from "zod";

const NO_STORE = { "Cache-Control": "no-store" } as const;

const sbomScanSchema = z.object({
  fileName: z
    .string()
    .min(1, "fileName is required")
    .refine((name) => !name.includes("..") && !name.startsWith("/"), {
      message: "fileName must not contain path traversal characters",
    }),
  content: z.string().min(1, "content is required"),
  repositoryId: z.string().optional(),
});

const handler = withErrorHandler(async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new AppError("Unauthorized", 401);
  }
  const userId = session.user.id;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new AppError("Request body must be valid JSON", 400);
  }

  const parsed = sbomScanSchema.safeParse(body);
  if (!parsed.success) {
    throw new AppError(
      parsed.error.issues.map((i) => i.message).join(", "),
      400,
    );
  }

  const { fileName, content, repositoryId } = parsed.data;

  // Enforce bounded payload size to protect Redis & worker memory
  const byteLength = Buffer.byteLength(content, "utf-8");
  if (byteLength > MAX_SBOM_BYTES) {
    throw new AppError(
      `Manifest file exceeds maximum allowed size of ${MAX_SBOM_BYTES} bytes (1MB)`,
      413,
    );
  }

  const { jobId, scanJobId } = await enqueueSbomScan({
    fileName,
    content,
    userId,
    repositoryId,
  });

  return NextResponse.json(
    {
      status: "queued",
      jobId,
      scanJobId,
      message: "SBOM scan job enqueued successfully",
      pollingUrl: `/api/sbom/scan/status/${scanJobId}`,
    },
    { status: 202, headers: NO_STORE },
  );
});

export const POST = withRateLimit(handler, {
  limit: 30,
  windowSeconds: 60,
  keyPrefix: "sbom:scan",
});

export const dynamic = "force-dynamic";
