import { describe, it, expect, vi, beforeEach } from "vitest";

const { mockPrisma, mockRedis, mockDLQInstance } = vi.hoisted(() => {
  const mockPrisma = {
    scanJob: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    auditLog: {
      create: vi.fn(),
    },
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
  });

  it("processes a valid package.json with vulnerabilities successfully", async () => {
    mockPrisma.scanJob.findUnique.mockResolvedValue({ id: "sj-1", status: "PENDING" });
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
      },
      opts: { attempts: 3 },
      attemptsMade: 0,
    } as any;

    const result = await processSbomJob(job);

    expect(result.scanId).toBe("sj-1");
    expect(result.totalDependencies).toBe(2);
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.status).toBe("VULNERABLE");

    // Marked PROCESSING first
    expect(mockPrisma.scanJob.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "sj-1" },
        data: expect.objectContaining({ status: "PROCESSING" }),
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

  it("skips re-processing if ScanJob is already COMPLETED (idempotency)", async () => {
    const cachedResult = {
      scanId: "sj-already-done",
      totalDependencies: 3,
      vulnerabilities: [],
      status: "CLEAN",
    };

    mockPrisma.scanJob.findUnique.mockResolvedValue({
      id: "sj-already-done",
      status: "COMPLETED",
    });
    mockRedis.get.mockResolvedValue(JSON.stringify(cachedResult));

    const job = {
      id: "job-repeat",
      data: {
        scanJobId: "sj-already-done",
        fileName: "package.json",
        content: "{}",
        userId: "user-1",
      },
      opts: { attempts: 3 },
      attemptsMade: 1,
    } as any;

    const result = await processSbomJob(job);
    expect(result).toEqual(cachedResult);
    expect(mockPrisma.auditLog.create).not.toHaveBeenCalled();
  });
});
