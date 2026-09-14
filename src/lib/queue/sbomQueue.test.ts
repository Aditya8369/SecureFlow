import { describe, it, expect, vi, beforeEach } from "vitest";

const { mockQueueInstance, MockQueue, mockPrisma, mockRedis } = vi.hoisted(() => {
  const mockQueueInstance = {
    add: vi.fn(),
    getJob: vi.fn(),
    getWaitingCount: vi.fn().mockResolvedValue(0),
    getActiveCount: vi.fn().mockResolvedValue(1),
    getCompletedCount: vi.fn().mockResolvedValue(10),
    getFailedCount: vi.fn().mockResolvedValue(1),
    getDelayedCount: vi.fn().mockResolvedValue(0),
  };

  class MockQueue {
    constructor() {
      Object.assign(this, mockQueueInstance);
    }
  }

  const mockPrisma = {
    scanJob: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
    scanResult: {
      findFirst: vi.fn(),
    },
    auditLog: {
      create: vi.fn(),
      findFirst: vi.fn(),
    },
  };

  const mockRedis = {
    get: vi.fn(),
    set: vi.fn(),
  };

  return { mockQueueInstance, MockQueue, mockPrisma, mockRedis };
});

vi.mock("bullmq", () => ({
  Queue: MockQueue,
  Worker: vi.fn(),
  UnrecoverableError: class UnrecoverableError extends Error {
    constructor(msg: string) {
      super(msg);
      this.name = "UnrecoverableError";
    }
  },
}));

vi.mock("./redis", () => ({
  redis: mockRedis,
}));

vi.mock("@/lib/prisma", () => ({
  default: mockPrisma,
}));

import {
  enqueueSbomScan,
  getSbomJobStatus,
  getSbomQueueMetrics,
  MAX_SBOM_BYTES,
} from "./sbomQueue";

describe("sbomQueue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQueueInstance.add.mockResolvedValue({ id: "test-job-id" });
  });

  describe("enqueueSbomScan", () => {
    it("creates a ScanJob record, creates AuditLog, and enqueues to BullMQ", async () => {
      mockPrisma.scanJob.create.mockResolvedValue({ id: "sj-101", status: "PENDING" });
      mockPrisma.auditLog.create.mockResolvedValue({ id: "audit-1" });

      const result = await enqueueSbomScan({
        fileName: "package.json",
        content: JSON.stringify({ dependencies: { express: "4.18.2" } }),
        userId: "user-abc",
        repositoryId: "repo-123",
        pullRequestId: "pr-456",
      });

      expect(result.scanJobId).toBe("sj-101");
      expect(result.jobId).toBe("sbom-sj-101");

      expect(mockPrisma.scanJob.create).toHaveBeenCalledWith({
        data: {
          repositoryId: "repo-123",
          pullRequestId: "pr-456",
          status: "PENDING",
          totalFiles: 1,
          scannedFiles: 0,
          vulnerabilitiesFound: 0,
        },
      });

      expect(mockPrisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            userId: "user-abc",
            action: "SBOM SCAN ENQUEUED",
            resource: "sj-101",
            metadata: expect.objectContaining({
              pullRequestId: "pr-456",
            }),
          }),
        }),
      );

      expect(mockQueueInstance.add).toHaveBeenCalledWith(
        "process-sbom",
        expect.objectContaining({
          scanJobId: "sj-101",
          fileName: "package.json",
          userId: "user-abc",
          pullRequestId: "pr-456",
        }),
        expect.objectContaining({
          jobId: "sbom-sj-101",
          attempts: 3,
        }),
      );
    });

    it("rejects payloads exceeding the maximum byte length", async () => {
      const hugeContent = "x".repeat(MAX_SBOM_BYTES + 10);

      await expect(
        enqueueSbomScan({
          fileName: "package.json",
          content: hugeContent,
          userId: "user-1",
        }),
      ).rejects.toThrow(/exceeds maximum size limit/);

      expect(mockPrisma.scanJob.create).not.toHaveBeenCalled();
      expect(mockQueueInstance.add).not.toHaveBeenCalled();
    });

    it("marks ScanJob as FAILED if BullMQ enqueue throws", async () => {
      mockPrisma.scanJob.create.mockResolvedValue({ id: "sj-fail", status: "PENDING" });
      mockPrisma.scanJob.update.mockResolvedValue({});
      mockQueueInstance.add.mockRejectedValueOnce(new Error("Redis connection refused"));

      await expect(
        enqueueSbomScan({
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
        }),
      ).rejects.toThrow("Redis connection refused");

      expect(mockPrisma.scanJob.update).toHaveBeenCalledWith({
        where: { id: "sj-fail" },
        data: {
          status: "FAILED",
          error: "Redis connection refused",
        },
      });
    });

    describe("stable deduplication (Finding 6)", () => {
      it("reuses existing ScanJob when BullMQ already has the logical job", async () => {
        const stableJobId = "sbom:repo-1-pr-1-sha1-pkg";
        mockQueueInstance.getJob.mockResolvedValue({
          id: stableJobId,
          data: { scanJobId: "sj-existing-bullmq" },
        });
        mockPrisma.scanJob.findUnique.mockResolvedValue({
          id: "sj-existing-bullmq",
          status: "PROCESSING",
        });

        const result = await enqueueSbomScan(
          {
            fileName: "package.json",
            content: "{}",
            userId: "user-1",
          },
          {
            jobId: stableJobId,
            dedupeKey: "webhook:repo-1:pr-1:sha1:package.json",
          },
        );

        expect(result).toEqual({
          jobId: stableJobId,
          scanJobId: "sj-existing-bullmq",
        });
        expect(mockPrisma.scanJob.create).not.toHaveBeenCalled();
        expect(mockQueueInstance.add).not.toHaveBeenCalled();
      });

      it("reuses existing ScanJob when PostgreSQL AuditLog already contains the dedupeKey", async () => {
        const dedupeKey = "webhook:repo-1:pr-1:sha1:package.json";
        mockQueueInstance.getJob.mockResolvedValue(null);
        mockPrisma.auditLog.findFirst.mockResolvedValue({
          resource: "sj-existing-pg",
          metadata: { scanJobId: "sj-existing-pg", dedupeKey },
        });
        mockPrisma.scanJob.findUnique.mockResolvedValue({
          id: "sj-existing-pg",
          status: "COMPLETED",
        });

        const result = await enqueueSbomScan(
          {
            fileName: "package.json",
            content: "{}",
            userId: "user-1",
          },
          {
            dedupeKey,
          },
        );

        expect(result.scanJobId).toBe("sj-existing-pg");
        expect(mockPrisma.scanJob.create).not.toHaveBeenCalled();
        expect(mockQueueInstance.add).not.toHaveBeenCalled();
      });

      it("deletes newly-created duplicate ScanJob if BullMQ concurrently returns an older job", async () => {
        mockQueueInstance.getJob.mockResolvedValue(null);
        mockPrisma.auditLog.findFirst.mockResolvedValue(null);
        mockPrisma.scanJob.create.mockResolvedValue({ id: "sj-racing-new" });
        mockPrisma.auditLog.create.mockResolvedValue({});
        mockPrisma.scanJob.delete.mockResolvedValue({});

        // BullMQ add returns existing job from another concurrent caller
        mockQueueInstance.add.mockResolvedValue({
          id: "sbom:repo-1-pr-1",
          data: { scanJobId: "sj-racing-existing" },
        });

        const result = await enqueueSbomScan(
          {
            fileName: "package.json",
            content: "{}",
            userId: "user-1",
          },
          {
            jobId: "sbom:repo-1-pr-1",
          },
        );

        expect(result).toEqual({
          jobId: "sbom:repo-1-pr-1",
          scanJobId: "sj-racing-existing",
        });
        // Verified orphaned duplicate was cleaned up
        expect(mockPrisma.scanJob.delete).toHaveBeenCalledWith({
          where: { id: "sj-racing-new" },
        });
      });
    });
  });

  describe("getSbomJobStatus", () => {
    it("returns null for non-existent job", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue(null);

      const status = await getSbomJobStatus("nonexistent-id");
      expect(status).toBeNull();
    });

    it("returns PENDING status when job is queued", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-pending",
        status: "PENDING",
        totalFiles: 1,
        scannedFiles: 0,
        vulnerabilitiesFound: 0,
        error: null,
        queuedAt: new Date("2026-09-14T10:00:00Z"),
        startedAt: null,
        completedAt: null,
      });

      const status = await getSbomJobStatus("sj-pending");
      expect(status).toMatchObject({
        scanJobId: "sj-pending",
        status: "PENDING",
        result: null,
        vulnerabilitiesFound: 0,
      });
    });

    it("returns COMPLETED status with cached result from Redis", async () => {
      const mockResult = {
        scanId: "sj-done",
        timestamp: "2026-09-14T10:01:00.000Z",
        totalDependencies: 1,
        vulnerabilities: [
          {
            dependency: { name: "lodash", version: "4.17.20" },
            severity: "HIGH",
            cveId: "CVE-MOCK-1234",
          },
        ],
        status: "VULNERABLE",
      };

      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-done",
        status: "COMPLETED",
        totalFiles: 1,
        scannedFiles: 1,
        vulnerabilitiesFound: 1,
        error: null,
        queuedAt: new Date("2026-09-14T10:00:00Z"),
        startedAt: new Date("2026-09-14T10:00:02Z"),
        completedAt: new Date("2026-09-14T10:00:05Z"),
      });

      mockRedis.get.mockResolvedValue(JSON.stringify(mockResult));

      const status = await getSbomJobStatus("sj-done");
      expect(status).not.toBeNull();
      expect(status!.status).toBe("COMPLETED");
      expect(status!.result).toEqual(mockResult);
      expect(status!.vulnerabilitiesFound).toBe(1);
    });

    it("falls back to AuditLog when Redis cache has expired", async () => {
      const mockResult = {
        scanId: "sj-audit",
        totalDependencies: 2,
        vulnerabilities: [],
        status: "CLEAN",
      };

      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-audit",
        status: "COMPLETED",
        totalFiles: 1,
        scannedFiles: 1,
        vulnerabilitiesFound: 0,
        error: null,
        queuedAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
      });

      mockRedis.get.mockResolvedValue(null);
      mockQueueInstance.getJob.mockResolvedValue(null);
      mockPrisma.auditLog.findFirst.mockResolvedValue({
        metadata: { result: mockResult },
      });

      const status = await getSbomJobStatus("sj-audit");
      expect(status).not.toBeNull();
      expect(status!.result).toEqual(mockResult);
    });

    it("falls back to ScanResult when Redis and AuditLog miss", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-scanresult-fallback",
        status: "COMPLETED",
        totalFiles: 1,
        scannedFiles: 1,
        vulnerabilitiesFound: 1,
        pullRequestId: "pr-fallback",
        error: null,
        queuedAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
      });

      mockRedis.get.mockResolvedValue(null);
      mockQueueInstance.getJob.mockResolvedValue(null);
      mockPrisma.auditLog.findFirst.mockResolvedValue(null);
      mockPrisma.scanResult.findFirst.mockResolvedValue({
        id: "sr-fallback",
        pullRequestId: "pr-fallback",
        policyDecision: "BLOCK",
        createdAt: new Date("2026-09-14T12:00:00Z"),
        findings: [
          {
            id: "f-1",
            severity: "HIGH",
            codeSnippet: "Dependency: lodash@4.17.20\nPatched: 4.17.21",
            explanation: "CVE-MOCK-1",
            remediation: "Upgrade lodash",
          },
        ],
      });

      const status = await getSbomJobStatus("sj-scanresult-fallback");
      expect(status).not.toBeNull();
      expect(status!.status).toBe("COMPLETED");
      expect(status!.result).not.toBeNull();
      expect(status!.result?.status).toBe("VULNERABLE");
    });
  });

  describe("getSbomQueueMetrics", () => {
    it("returns counts across waiting, active, completed, failed, delayed", async () => {
      const metrics = await getSbomQueueMetrics();
      expect(metrics).toEqual({
        waiting: 0,
        active: 1,
        completed: 10,
        failed: 1,
        delayed: 0,
      });
    });
  });
});
