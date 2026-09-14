import { describe, it, expect, vi, beforeEach } from "vitest";

const { authMock, enqueueSbomScanMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  enqueueSbomScanMock: vi.fn(),
}));

vi.mock("@/auth", () => ({ auth: authMock }));

vi.mock("@/lib/queue/sbomQueue", () => ({
  enqueueSbomScan: enqueueSbomScanMock,
  MAX_SBOM_BYTES: 1024 * 1024,
}));

vi.mock("@/lib/middleware/error-handler", () => {
  class AppError extends Error {
    statusCode: number;
    constructor(msg: string, code = 400) {
      super(msg);
      this.statusCode = code;
    }
  }

  return {
    AppError,
    withErrorHandler:
      (fn: (...args: unknown[]) => unknown) =>
      async (...args: unknown[]) => {
        try {
          return await fn(...args);
        } catch (err: unknown) {
          const e = err as { statusCode?: number; message?: string };
          return new Response(JSON.stringify({ error: e.message }), {
            status: e.statusCode ?? 500,
            headers: { "content-type": "application/json" },
          });
        }
      },
  };
});

vi.mock("@/lib/middleware/rate-limit", () => ({
  withRateLimit: <T>(handler: T): T => handler,
}));

import { POST } from "./route";

function makePostRequest(body: unknown) {
  return new Request("http://localhost/api/sbom/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  }) as any;
}

describe("POST /api/sbom/scan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authMock.mockResolvedValue({ user: { id: "user-test" } });
    enqueueSbomScanMock.mockResolvedValue({
      jobId: "sbom-sj-123",
      scanJobId: "sj-123",
    });
  });

  it("returns 401 Unauthorized when session is missing", async () => {
    authMock.mockResolvedValue(null);

    const req = makePostRequest({ fileName: "package.json", content: "{}" });
    const res = await POST(req);

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Unauthorized" });
    expect(enqueueSbomScanMock).not.toHaveBeenCalled();
  });

  it("returns 400 Bad Request when body is invalid JSON", async () => {
    const req = makePostRequest("not-valid-json");
    const res = await POST(req);

    expect(res.status).toBe(400);
    expect(enqueueSbomScanMock).not.toHaveBeenCalled();
  });

  it("returns 400 Bad Request when fileName is missing", async () => {
    const req = makePostRequest({ content: "{}" });
    const res = await POST(req);

    expect(res.status).toBe(400);
    expect(enqueueSbomScanMock).not.toHaveBeenCalled();
  });

  it("returns 400 Bad Request when content is missing", async () => {
    const req = makePostRequest({ fileName: "package.json" });
    const res = await POST(req);

    expect(res.status).toBe(400);
    expect(enqueueSbomScanMock).not.toHaveBeenCalled();
  });

  it("returns 400 Bad Request when fileName contains path traversal", async () => {
    const req = makePostRequest({
      fileName: "../../etc/passwd",
      content: "{}",
    });
    const res = await POST(req);

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: expect.stringContaining("path traversal"),
    });
    expect(enqueueSbomScanMock).not.toHaveBeenCalled();
  });

  it("returns 413 Payload Too Large when manifest exceeds 1MB", async () => {
    const oversized = "a".repeat(1024 * 1024 + 50);
    const req = makePostRequest({
      fileName: "package.json",
      content: oversized,
    });
    const res = await POST(req);

    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({
      error: expect.stringContaining("exceeds maximum allowed size"),
    });
    expect(enqueueSbomScanMock).not.toHaveBeenCalled();
  });

  it("enqueues scan job and returns 202 Accepted with job handles", async () => {
    const req = makePostRequest({
      fileName: "package.json",
      content: JSON.stringify({ dependencies: { express: "4.18.2" } }),
      repositoryId: "repo-xyz",
    });

    const res = await POST(req);

    expect(res.status).toBe(202);
    expect(res.headers.get("Cache-Control")).toBe("no-store");

    const body = await res.json();
    expect(body).toEqual({
      status: "queued",
      jobId: "sbom-sj-123",
      scanJobId: "sj-123",
      message: "SBOM scan job enqueued successfully",
      pollingUrl: "/api/sbom/scan/status/sj-123",
    });

    expect(enqueueSbomScanMock).toHaveBeenCalledWith({
      fileName: "package.json",
      content: JSON.stringify({ dependencies: { express: "4.18.2" } }),
      userId: "user-test",
      repositoryId: "repo-xyz",
    });
  });
});
