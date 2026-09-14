import { describe, it, expect, vi, beforeEach } from "vitest";

const { mockPrisma, mockRedis, mockDLQInstance } = vi.hoisted(() => {
  const mockPrisma = {
    scanJob: {
      findUnique: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
    },
    scanResult: {
      create: vi.fn(),
      findFirst: vi.fn(),
    },
    auditLog: {
      create: vi.fn(),
      findFirst: vi.fn(),
    },
    $transaction: vi.fn(),
  };

  const mockRedis = {
    get: vi.fn(),
    set: vi.fn().mockResolvedValue("OK"),
  };

  const mockDLQInstance = {
    add: vi.fn().mockResolvedValue({ id: "dlq-job-1" }),
  };

  return { mockPrisma, mockRedis, mockDLQInstance };
});

vi.mock("bullmq", () => {
  class UnrecoverableError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "UnrecoverableError";
    }
  }

  class MockWorker {
    on = vi.fn();
    close = vi.fn().mockResolvedValue(undefined);
  }

  class MockQueue {
    add = mockDLQInstance.add;
  }

  return {
    Worker: MockWorker,
    Queue: MockQueue,
    UnrecoverableError,
  };
});

vi.mock("./redis", () => ({
  redis: mockRedis,
}));

vi.mock("@/lib/prisma", () => ({
  default: mockPrisma,
}));

import { processSbomJob } from "./sbomWorker";
import { UnrecoverableError } from "bullmq";

describe("sbomWorker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPrisma.scanJob.updateMany.mockResolvedValue({ count: 1 });
    mockPrisma.$transaction.mockImplementation(async (cb: (tx: typeof mockPrisma) => Promise<unknown>) => cb(mockPrisma));
    mockPrisma.scanResult.create.mockResolvedValue({ id: "sr-1" });
  });

  it("processes a valid package.json with vulnerabilities successfully and persists ScanResult + Findings", async () => {
    mockPrisma.scanJob.findUnique.mockResolvedValue({ id: "sj-1", status: "PENDING", pullRequestId: "pr-1" });
    mockPrisma.scanJob.update.mockResolvedValue({});
    mockPrisma.auditLog.create.mockResolvedValue({});

    const job = {
      id: "job-1",
      data: {
        scanJobId: "sj-1",
        fileName: "package.json",
        content: JSON.stringify({
          dependencies: {
            lodash: "^4.17.20", // known high in mock cve db
            cleanpkg: "1.0.0",
          },
        }),
        userId: "user-1",
        repositoryId: "repo-1",
        pullRequestId: "pr-1",
      },
      opts: { attempts: 3 },
      attemptsMade: 0,
    } as any;

    const result = await processSbomJob(job);

    expect(result.scanId).toBe("sj-1");
    expect(result.totalDependencies).toBe(2);
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.status).toBe("VULNERABLE");

    // Concurrency-safe transition to PROCESSING
    expect(mockPrisma.scanJob.updateMany).toHaveBeenCalledWith({
      where: { id: "sj-1", status: "PENDING" },
      data: expect.objectContaining({ status: "PROCESSING" }),
    });

    // Transaction executed
    expect(mockPrisma.$transaction).toHaveBeenCalledOnce();

    // Persisted ScanResult with nested Findings
    expect(mockPrisma.scanResult.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          pullRequestId: "pr-1",
          policyDecision: "BLOCK",
          findings: {
            create: expect.arrayContaining([
              expect.objectContaining({
                type: "VULNERABILITY",
                fileLocation: "package.json",
                fingerprint: expect.any(String),
                codeSnippet: expect.stringContaining("lodash"),
              }),
            ]),
          },
        }),
      }),
    );

    // Marked COMPLETED
    expect(mockPrisma.scanJob.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "sj-1" },
        data: expect.objectContaining({
          status: "COMPLETED",
          scannedFiles: 1,
          vulnerabilitiesFound: result.vulnerabilities.length,
          policyDecision: "BLOCK",
        }),
      }),
    );

    // Persisted to AuditLog
    expect(mockPrisma.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userId: "user-1",
          action: "SBOM SCAN COMPLETED",
          resource: "sj-1",
          metadata: expect.objectContaining({
            pullRequestId: "pr-1",
          }),
        }),
      }),
    );

    // Cached in Redis
    expect(mockRedis.set).toHaveBeenCalledWith(
      "sbom:result:sj-1",
      JSON.stringify(result),
      "EX",
      86400,
    );
  });

  it("processes a clean requirements.txt with no vulnerabilities", async () => {
    mockPrisma.scanJob.findUnique.mockResolvedValue({ id: "sj-2", status: "PENDING" });
    mockPrisma.scanJob.update.mockResolvedValue({});

    const job = {
      id: "job-2",
      data: {
        scanJobId: "sj-2",
        fileName: "requirements.txt",
        content: "flask==2.3.2\npytest==7.4.0\n",
        userId: "user-2",
      },
      opts: { attempts: 3 },
      attemptsMade: 0,
    } as any;

    const result = await processSbomJob(job);

    expect(result.totalDependencies).toBe(2);
    expect(result.vulnerabilities.length).toBe(0);
    expect(result.status).toBe("CLEAN");

    expect(mockPrisma.scanJob.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "sj-2" },
        data: expect.objectContaining({
          status: "COMPLETED",
          policyDecision: "PASS",
        }),
      }),
    );
  });

  it("throws UnrecoverableError and marks ScanJob FAILED for malformed JSON", async () => {
    mockPrisma.scanJob.findUnique.mockResolvedValue({ id: "sj-malformed", status: "PENDING" });
    mockPrisma.scanJob.update.mockResolvedValue({});

    const job = {
      id: "job-bad",
      data: {
        scanJobId: "sj-malformed",
        fileName: "package.json",
        content: "{ invalid json ...",
        userId: "user-1",
      },
      opts: { attempts: 3 },
      attemptsMade: 0,
    } as any;

    await expect(processSbomJob(job)).rejects.toThrow(UnrecoverableError);

    expect(mockPrisma.scanJob.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "sj-malformed" },
        data: expect.objectContaining({
          status: "FAILED",
          error: expect.stringContaining("Invalid JSON syntax"),
        }),
      }),
    );
  });

  describe("durable idempotency & completed-state recovery (Finding 2)", () => {
    const cachedResult = {
      scanId: "sj-done-1",
      timestamp: "2026-09-14T10:00:00.000Z",
      totalDependencies: 3,
      vulnerabilities: [],
      status: "CLEAN" as const,
    };

    it("1. COMPLETED + Redis hit returns cached result without reprocessing", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-done-1",
        status: "COMPLETED",
      });
      mockRedis.get.mockResolvedValue(JSON.stringify(cachedResult));

      const job = {
        id: "job-redis-hit",
        data: {
          scanJobId: "sj-done-1",
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
        },
        opts: { attempts: 3 },
        attemptsMade: 1,
      } as any;

      const result = await processSbomJob(job);
      expect(result).toEqual(cachedResult);
      expect(mockPrisma.scanJob.updateMany).not.toHaveBeenCalled();
      expect(mockPrisma.scanJob.update).not.toHaveBeenCalled();
      expect(mockPrisma.auditLog.create).not.toHaveBeenCalled();
    });

    it("2. COMPLETED + Redis miss recovers from PostgreSQL AuditLog without reprocessing", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-done-2",
        status: "COMPLETED",
      });
      mockRedis.get.mockResolvedValue(null);
      mockPrisma.auditLog.findFirst.mockResolvedValue({
        metadata: { result: cachedResult },
      });

      const job = {
        id: "job-redis-miss",
        data: {
          scanJobId: "sj-done-2",
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
        },
        opts: { attempts: 3 },
        attemptsMade: 1,
      } as any;

      const result = await processSbomJob(job);
      expect(result).toEqual(cachedResult);
      expect(mockPrisma.auditLog.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ resource: "sj-done-2" }),
        }),
      );
      expect(mockPrisma.scanJob.updateMany).not.toHaveBeenCalled();
      expect(mockPrisma.scanJob.update).not.toHaveBeenCalled();
      expect(mockPrisma.auditLog.create).not.toHaveBeenCalled();
    });

    it("3. COMPLETED + Redis unavailable recovers from PostgreSQL without reprocessing", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-done-3",
        status: "COMPLETED",
      });
      mockRedis.get.mockRejectedValue(new Error("Redis connection timed out"));
      mockPrisma.auditLog.findFirst.mockResolvedValue({
        metadata: { result: cachedResult },
      });

      const job = {
        id: "job-redis-err",
        data: {
          scanJobId: "sj-done-3",
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
        },
        opts: { attempts: 3 },
        attemptsMade: 1,
      } as any;

      const result = await processSbomJob(job);
      expect(result).toEqual(cachedResult);
      expect(mockPrisma.scanJob.updateMany).not.toHaveBeenCalled();
      expect(mockPrisma.auditLog.create).not.toHaveBeenCalled();
    });

    it("4. COMPLETED recovers from ScanResult when AuditLog has no metadata", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-done-4",
        status: "COMPLETED",
        pullRequestId: "pr-4",
      });
      mockRedis.get.mockResolvedValue(null);
      mockPrisma.auditLog.findFirst.mockResolvedValue(null);
      mockPrisma.scanResult.findFirst.mockResolvedValue({
        id: "sr-4",
        pullRequestId: "pr-4",
        policyDecision: "BLOCK",
        createdAt: new Date("2026-09-14T12:00:00Z"),
        findings: [
          {
            id: "f-1",
            severity: "HIGH",
            codeSnippet: "Dependency: lodash@4.17.20\nPatched: 4.17.21",
            explanation: "Detected known vulnerability CVE-MOCK-1234 in lodash.",
            remediation: "Update lodash to version 4.17.21 or higher.",
          },
        ],
      });

      const job = {
        id: "job-scanresult-recovery",
        data: {
          scanJobId: "sj-done-4",
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
          pullRequestId: "pr-4",
        },
        opts: { attempts: 3 },
        attemptsMade: 1,
      } as any;

      const result = await processSbomJob(job);
      expect(result.scanId).toBe("sj-done-4");
      expect(result.status).toBe("VULNERABLE");
      expect(result.vulnerabilities.length).toBe(1);
      expect(mockPrisma.scanJob.updateMany).not.toHaveBeenCalled();
      expect(mockPrisma.scanJob.update).not.toHaveBeenCalled();
      expect(mockPrisma.auditLog.create).not.toHaveBeenCalled();
    });

    it("5. throws UnrecoverableError when COMPLETED result cannot be recovered from any store", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({
        id: "sj-unrecoverable",
        status: "COMPLETED",
        pullRequestId: null,
      });
      mockRedis.get.mockResolvedValue(null);
      mockPrisma.auditLog.findFirst.mockResolvedValue(null);

      const job = {
        id: "job-unrecoverable",
        data: {
          scanJobId: "sj-unrecoverable",
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
        },
        opts: { attempts: 3 },
        attemptsMade: 1,
      } as any;

      await expect(processSbomJob(job)).rejects.toThrow(UnrecoverableError);
      expect(mockPrisma.scanJob.updateMany).not.toHaveBeenCalled();
      expect(mockPrisma.scanJob.update).not.toHaveBeenCalled();
    });

    it("6. handles duplicate worker delivery gracefully when another worker already PROCESSING", async () => {
      mockPrisma.scanJob.findUnique
        .mockResolvedValueOnce({ id: "sj-racing", status: "PENDING" })
        .mockResolvedValueOnce({ id: "sj-racing", status: "PROCESSING" });
      mockPrisma.scanJob.updateMany.mockResolvedValue({ count: 0 }); // updateMany claimed by another worker

      const job = {
        id: "job-duplicate-delivery",
        data: {
          scanJobId: "sj-racing",
          fileName: "package.json",
          content: "{}",
          userId: "user-1",
        },
        opts: { attempts: 3 },
        attemptsMade: 0,
      } as any;

      const result = await processSbomJob(job);
      expect(result.scanId).toBe("sj-racing");
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
      expect(mockPrisma.auditLog.create).not.toHaveBeenCalled();
    });
  });

  describe("transaction failure safety (Finding 3)", () => {
    it("does not mark ScanJob COMPLETED if transaction fails", async () => {
      mockPrisma.scanJob.findUnique.mockResolvedValue({ id: "sj-tx-fail", status: "PENDING" });
      mockPrisma.$transaction.mockRejectedValue(new Error("Database write collision"));

      const job = {
        id: "job-tx-fail",
        data: {
          scanJobId: "sj-tx-fail",
          fileName: "package.json",
          content: JSON.stringify({ dependencies: { express: "4.18.2" } }),
          userId: "user-1",
          pullRequestId: "pr-fail",
        },
        opts: { attempts: 3 },
        attemptsMade: 0,
      } as any;

      await expect(processSbomJob(job)).rejects.toThrow("Database write collision");
      // Outside transaction, scanJob was only marked PROCESSING, never COMPLETED
      expect(mockPrisma.scanJob.update).not.toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: "COMPLETED" }),
        }),
      );
    });
  });
});
