/**
 * SBOM Worker — Background worker for processing queued SBOM scans.
 *
 * Consumes jobs from the 'sbom-scans' BullMQ queue, performs manifest dependency
 * parsing and CVE matching, updates the ScanJob lifecycle in PostgreSQL,
 * durably persists results to AuditLog and Redis cache, and routes permanent
 * failures to the Dead Letter Queue (DLQ).
 */

import { Worker, Job, UnrecoverableError } from "bullmq";
import { redis } from "./redis";
import prisma from "@/lib/prisma";
import { parseManifestFile } from "@/lib/sbom/dependency-parser";
import { matchVulnerabilities } from "@/lib/sbom/vulnerability-matcher";
import { sbomDLQ, SbomJobData, SBOM_QUEUE_NAME } from "./sbomQueue";
import type { SbomScanResult } from "@/types/sbom";
import { sanitizeAuditLogInput } from "@/lib/audit/minimization";
import { createLogger } from "@/lib/logger";

const log = createLogger({ context: { component: "sbom-worker" } });

export const DEFAULT_SBOM_CONCURRENCY = 5;

/**
 * Process a single SBOM scan job.
 *
 * Exported so unit tests can invoke it directly without reaching into BullMQ internals.
 */
export async function processSbomJob(job: Job<SbomJobData>): Promise<SbomScanResult> {
  const { scanJobId, fileName, content, userId, repositoryId } = job.data;

  // 1. Idempotency check: if this scan is already completed, return cached/existing result
  const existingJob = await prisma.scanJob.findUnique({
    where: { id: scanJobId },
  });

  if (existingJob?.status === "COMPLETED") {
    log.info("SBOM scan job already completed, skipping re-processing", { scanJobId });
    if (redis && typeof redis.get === "function") {
      const cached = await redis.get(`sbom:result:${scanJobId}`);
      if (cached) return JSON.parse(cached);
    }
  }

  // 2. Mark ScanJob as PROCESSING
  await prisma.scanJob
    .update({
      where: { id: scanJobId },
      data: {
        status: "PROCESSING",
        startedAt: new Date(),
      },
    })
    .catch(() => {});

  try {
    // 3. Early validation of manifest syntax — avoid retrying inherently malformed inputs
    if (fileName.endsWith("package.json")) {
      try {
        JSON.parse(content);
      } catch (parseErr) {
        const errorMsg = `Invalid JSON syntax in ${fileName}`;
        await prisma.scanJob
          .update({
            where: { id: scanJobId },
            data: {
              status: "FAILED",
              error: errorMsg,
              completedAt: new Date(),
            },
          })
          .catch(() => {});
        throw new UnrecoverableError(errorMsg);
      }
    }

    // 4. Perform dependency parsing and vulnerability matching
    const dependencies = parseManifestFile(content, fileName);
    const vulnerabilities = matchVulnerabilities(dependencies);

    const result: SbomScanResult = {
      scanId: scanJobId,
      timestamp: new Date(),
      totalDependencies: dependencies.length,
      vulnerabilities,
      status: vulnerabilities.length > 0 ? "VULNERABLE" : "CLEAN",
    };

    // 5. Durably persist completion in database
    await prisma.scanJob.update({
      where: { id: scanJobId },
      data: {
        status: "COMPLETED",
        scannedFiles: 1,
        vulnerabilitiesFound: vulnerabilities.length,
        policyDecision: vulnerabilities.length > 0 ? "BLOCK" : "PASS",
        completedAt: new Date(),
      },
    });

    // 6. Record completed event with full result in PostgreSQL AuditLog
    if (userId) {
      await prisma.auditLog.create({
        data: sanitizeAuditLogInput({
          userId,
          action: "SBOM Scan Completed",
          resource: scanJobId,
          decision: result.status,
          metadata: {
            scanJobId,
            fileName,
            repositoryId: repositoryId ?? null,
            totalDependencies: dependencies.length,
            vulnerabilitiesCount: vulnerabilities.length,
            result,
          },
        }),
      });
    }

    // 7. Cache in Redis for fast status polling retrieval (24 hour TTL)
    if (redis && typeof redis.set === "function") {
      try {
        await redis.set(`sbom:result:${scanJobId}`, JSON.stringify(result), "EX", 86_400);
      } catch (cacheErr) {
        log.warn("Failed to cache SBOM result in Redis", {
          scanJobId,
          error: (cacheErr as Error).message,
        });
      }
    }

    log.info("SBOM scan job completed successfully", {
      scanJobId,
      totalDependencies: dependencies.length,
      vulnerabilitiesCount: vulnerabilities.length,
    });

    return result;
  } catch (err) {
    const isUnrecoverable = err instanceof UnrecoverableError;
    const errorMessage = err instanceof Error ? err.message : String(err);

    // If unrecoverable, mark FAILED immediately
    if (isUnrecoverable) {
      await prisma.scanJob
        .update({
          where: { id: scanJobId },
          data: {
            status: "FAILED",
            error: errorMessage,
            completedAt: new Date(),
          },
        })
        .catch(() => {});
      throw err;
    }

    // For transient errors, check if this was the last attempt
    const maxAttempts = job.opts.attempts ?? 3;
    if (job.attemptsMade >= maxAttempts - 1) {
      await prisma.scanJob
        .update({
          where: { id: scanJobId },
          data: {
            status: "FAILED",
            error: errorMessage,
            completedAt: new Date(),
          },
        })
        .catch(() => {});
    }

    throw err;
  }
}

const concurrency = parseInt(
  process.env.SBOM_WORKER_CONCURRENCY ?? String(DEFAULT_SBOM_CONCURRENCY),
  10,
);

export const sbomWorker = new Worker<SbomJobData>(SBOM_QUEUE_NAME, processSbomJob, {
  connection: redis as any,
  concurrency: Number.isFinite(concurrency) && concurrency > 0 ? concurrency : DEFAULT_SBOM_CONCURRENCY,
});

sbomWorker.on("completed", (job: Job) => {
  log.info("SBOM job completed", { jobId: job.id });
});

sbomWorker.on("failed", async (job: Job | undefined, err: Error) => {
  if (!job) return;

  const maxAttempts = job.opts.attempts ?? 3;
  const isUnrecoverable = err instanceof UnrecoverableError || err.name === "UnrecoverableError";
  const exhausted = job.attemptsMade >= maxAttempts;

  if (!exhausted && !isUnrecoverable) {
    log.warn("SBOM job failed, retrying with backoff", {
      jobId: job.id,
      attempt: job.attemptsMade,
      maxAttempts,
      reason: err.message,
    });
    return;
  }

  log.error("SBOM job permanently failed, routing to DLQ", {
    jobId: job.id,
    attempts: job.attemptsMade,
    reason: err.message,
  });

  try {
    await sbomDLQ.add("failed-sbom-scan", {
      originalJobId: job.id,
      data: job.data,
      failedReason: err.message,
      failedAt: new Date().toISOString(),
      attemptsMade: job.attemptsMade,
      unrecoverable: isUnrecoverable,
    });
  } catch (dlqErr) {
    log.error("Failed to route SBOM job to DLQ", {
      jobId: job.id,
      error: dlqErr instanceof Error ? dlqErr.message : String(dlqErr),
    });
  }
});
