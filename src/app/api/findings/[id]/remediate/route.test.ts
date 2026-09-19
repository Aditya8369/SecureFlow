import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest, NextResponse } from "next/server";

const { authMock, findingFindUnique, patchUpsert, generatePatchMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  findingFindUnique: vi.fn(),
  patchUpsert: vi.fn(),
  generatePatchMock: vi.fn(),
}));

vi.mock("@/auth", () => ({ auth: authMock }));

vi.mock("@/lib/prisma", () => ({
  default: {
    finding: { findUnique: findingFindUnique },
    remediationPatch: { upsert: patchUpsert },
  },
}));

vi.mock("@/ai/flows/generate-remediation-patch", () => ({
  generateRemediationPatchFlow: generatePatchMock,
}));

vi.mock("@/lib/middleware/rate-limit", () => ({
  TIERS: { AI_STREAM: { limit: 20, windowSeconds: 60, fallbackStrategy: "fail-closed" } },
  withRateLimit: <T>(handler: T): T => handler,
}));

import { POST } from "./route";

const mockFinding = {
  id: "finding-1",
  type: "VULNERABILITY",
  fileLocation: "src/auth.ts",
  codeSnippet: "const token = jwt.decode(t);",
  explanation: "Unverified token payload",
  remediation: "Verify signature with jwt.verify",
  scanResult: {
    pullRequest: {
      repository: {
        userId: "user-1",
      },
    },
  },
};

describe("POST /api/findings/[id]/remediate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authMock.mockResolvedValue({ user: { id: "user-1" } });
    findingFindUnique.mockResolvedValue(mockFinding);
    generatePatchMock.mockResolvedValue({
      patchDiff: "--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1 +1 @@\n-jwt.decode\n+jwt.verify",
      explanation: "Verify token signature",
    });
    patchUpsert.mockImplementation(async ({ where, create, update }) => ({
      ...create,
      ...update,
      id: `patch-${where.findingId}`,
    }));
  });

  it("returns 401 if caller is unauthenticated", async () => {
    authMock.mockResolvedValue(null);
    const req = new NextRequest("http://localhost:3000/api/findings/finding-1/remediate", {
      method: "POST",
    });
    const res = await POST(req, { params: Promise.resolve({ id: "finding-1" }) });

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBe("Unauthorized");
  });

  it("returns 404 if finding is not found", async () => {
    findingFindUnique.mockResolvedValue(null);
    const req = new NextRequest("http://localhost:3000/api/findings/finding-missing/remediate", {
      method: "POST",
    });
    const res = await POST(req, { params: Promise.resolve({ id: "finding-missing" }) });

    expect(res.status).toBe(404);
    const data = await res.json();
    expect(data.error).toBe("Finding not found");
  });

  it("returns 403 Forbidden if finding belongs to another user (prevents IDOR)", async () => {
    findingFindUnique.mockResolvedValue({
      ...mockFinding,
      scanResult: {
        pullRequest: {
          repository: {
            userId: "user-other",
          },
        },
      },
    });

    const req = new NextRequest("http://localhost:3000/api/findings/finding-1/remediate", {
      method: "POST",
    });
    const res = await POST(req, { params: Promise.resolve({ id: "finding-1" }) });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toMatch(/Forbidden: You do not have access to this finding/i);
    expect(generatePatchMock).not.toHaveBeenCalled();
    expect(patchUpsert).not.toHaveBeenCalled();
  });

  it("generates remediation patch and persists it when user owns repository", async () => {
    const req = new NextRequest("http://localhost:3000/api/findings/finding-1/remediate", {
      method: "POST",
    });
    const res = await POST(req, { params: Promise.resolve({ id: "finding-1" }) });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.explanation).toBe("Verify token signature");
    expect(data.patch.patchDiff).toContain("--- a/src/auth.ts");

    expect(findingFindUnique).toHaveBeenCalledWith({
      where: { id: "finding-1" },
      select: expect.objectContaining({
        id: true,
        type: true,
        codeSnippet: true,
        fileLocation: true,
        explanation: true,
        remediation: true,
        scanResult: {
          select: {
            pullRequest: {
              select: {
                repository: {
                  select: { userId: true },
                },
              },
            },
          },
        },
      }),
    });

    expect(generatePatchMock).toHaveBeenCalledWith({
      vulnerableCode: "const token = jwt.decode(t);",
      findingDescription: "Unverified token payload",
      filePath: "src/auth.ts",
    });

    expect(patchUpsert).toHaveBeenCalledWith({
      where: { findingId: "finding-1" },
      update: {
        patchDiff: "--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1 +1 @@\n-jwt.decode\n+jwt.verify",
        status: "GENERATED",
      },
      create: {
        findingId: "finding-1",
        patchDiff: "--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1 +1 @@\n-jwt.decode\n+jwt.verify",
        status: "GENERATED",
      },
    });
  });
});
