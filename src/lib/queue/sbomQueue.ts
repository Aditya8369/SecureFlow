/**
 * SBOM Queue — Redis/BullMQ job queue for Software Bill of Materials (SBOM) scans.
 *
 * Offloads manifest dependency parsing and CVE vulnerability matching from
 * Next.js API routes and webhook handlers to background workers.
 *
 * Usage:
 *   import { enqueueSbomScan, getSbomJobStatus } from '@/lib/queue/sbomQueue';
 *   const { jobId, scanJobId } = await enqueueSbomScan({ fileName, content, userId });
 *   const status = await getSbomJobStatus(scanJobId);
 */

import { Queue, Job } from "bullmq";
import { redis } from "./redis";
import prisma from "@/lib/prisma";
import type { ScanJobStatus } from "@prisma/client";
import type { SbomScanResult } from "@/types/sbom";
import { sanitizeAuditLogInput } from "@/lib/audit/minimization";

export const SBOM_QUEUE_NAME = "sbom-scans";
export const SBOM_DLQ_NAME = "sbom-scans-dlq";

/** Maximum allowed manifest content size (1 MB default). */
export const MAX_SBOM_BYTES = 1024 * 1024;

export interface SbomJobData {
  scanJobId: string;
  fileName: string;
  content: string;
  userId: string;
  repositoryId?: string;
}

export const sbomQueue = new Queue<SbomJobData>(SBOM_QUEUE_NAME, {
  connection: redis as any,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: "exponential",
      delay: 3000,
    },
    removeOnComplete: { age: 86_400 }, // 24 hours
    removeOnFail: { age: 172_800 }, // 48 hours
  },
});

export const sbomDLQ = new Queue(SBOM_DLQ_NAME, {
  connection: redis as any,
});

export interface EnqueueSbomOptions {
  jobId?: string;
}

/**
 * Enqueue an SBOM scan job.
 *
 * Creates a persistent ScanJob record in PostgreSQL for lifecycle tracking,
 * records an initial AuditLog event for ownership verification,
 * and adds the job to the BullMQ Redis queue with deterministic deduplication.
 */
export async function enqueueSbomScan(
  data: Omit<SbomJobData, "scanJobId">,
  options: EnqueueSbomOptions = {},
): Promise<{ jobId: string; scanJobId: string }> {
  // Validate content size
  const byteLength = Buffer.byteLength(data.content, "utf-8");
  if (byteLength > MAX_SBOM_BYTES) {
    throw new Error(`Manifest file exceeds maximum size limit of ${MAX_SBOM_BYTES} bytes`);
  }

  // 1. Create persistent ScanJob record in PostgreSQL
  const scanJob = await prisma.scanJob.create({
    data: {
      repositoryId: data.repositoryId || null,
      status: "PENDING",
      totalFiles: 1,
      scannedFiles: 0,
      vulnerabilitiesFound: 0,
    },
  });

  // 2. Create AuditLog entry linking user to this scanJob for authorization and durability
  if (data.userId) {
    await prisma.auditLog.create({
      data: sanitizeAuditLogInput({
        userId: data.userId,
        action: "SBOM Scan Enqueued",
        resource: scanJob.id,
        metadata: {
          scanJobId: scanJob.id,
          fileName: data.fileName,
          repositoryId: data.repositoryId ?? null,
        },
      }),
    });
  }

  const jobId = options.jobId ?? `sbom-${scanJob.id}`;
  const jobPayload: SbomJobData = {
    ...data,
    scanJobId: scanJob.id,
  };

  // Mock DB support for CI / test environments without Redis
  if (process.env.NEXT_PUBLIC_MOCK_DB === "true") {
    return { jobId, scanJobId: scanJob.id };
  }

  try {
    await sbomQueue.add("process-sbom", jobPayload, {
      jobId,
      priority: 1,
      attempts: 3,
      backoff: { type: "exponential", delay: 3000 },
    });
  } catch (err) {
    // If Redis enqueue fails, mark the ScanJob as FAILED so it does not stay PENDING forever
    await prisma.scanJob
      .update({
        where: { id: scanJob.id },
        data: {
          status: "FAILED",
          error: err instanceof Error ? err.message : "Failed to enqueue scan job",
        },
      })
      .catch(() => {});

    throw err;
  }

  return { jobId, scanJobId: scanJob.id };
}

export interface SbomJobStatusInfo {
  scanJobId: string;
  status: ScanJobStatus;
  totalFiles: number;
  scannedFiles: number;
  vulnerabilitiesFound: number;
  result: SbomScanResult | null;
  error: string | null;
  queuedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
}

/**
 * Get the status of an SBOM scan job.
 *
 * Checks the database ScanJob row, cached result in Redis, and fallback AuditLog metadata.
 */
export async function getSbomJobStatus(scanJobId: string): Promise<SbomJobStatusInfo | null> {
  const job = await prisma.scanJob.findUnique({
    where: { id: scanJobId },
  });

  if (!job) return null;

  let result: SbomScanResult | null = null;

  // If completed, attempt to fetch the full SbomScanResult from Redis cache or BullMQ returnvalue
  if (job.status === "COMPLETED") {
    try {
      if (redis && typeof redis.get === "function") {
        const cached = await redis.get(`sbom:result:${scanJobId}`);
        if (cached) {
          result = JSON.parse(cached);
        }
      }
      if (!result) {
        const bullJob = await sbomQueue.getJob(`sbom-${scanJobId}`);
        if (bullJob?.returnvalue) {
          result = bullJob.returnvalue;
        }
      }
    } catch {
      // Non-fatal if Redis read fails; database status is authoritative
    }

    // Fallback to AuditLog metadata if Redis cache expired
    if (!result) {
      try {
        const audit = await prisma.auditLog.findFirst({
          where: { resource: scanJobId, action: "SBOM SCAN COMPLETED" },
          select: { metadata: true },
        });
        if (audit?.metadata && typeof audit.metadata === "object") {
          const meta = audit.metadata as Record<string, unknown>;
          if (meta.result) {
            result = meta.result as SbomScanResult;
          }
        }
      } catch {
        // Fallback read error ignored
      }
    }
  }

  return {
    scanJobId: job.id,
    status: job.status,
    totalFiles: job.totalFiles,
    scannedFiles: job.scannedFiles,
    vulnerabilitiesFound: job.vulnerabilitiesFound,
    result,
    error: job.error,
    queuedAt: job.queuedAt,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
  };
}

/**
 * Queue metrics for monitoring.
 */
export async function getSbomQueueMetrics(): Promise<{
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
}> {
  const [waiting, active, completed, failed, delayed] = await Promise.all([
    sbomQueue.getWaitingCount(),
    sbomQueue.getActiveCount(),
    sbomQueue.getCompletedCount(),
    sbomQueue.getFailedCount(),
    sbomQueue.getDelayedCount(),
  ]);

  return { waiting, active, completed, failed, delayed };
}
