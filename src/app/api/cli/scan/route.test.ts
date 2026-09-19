import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const { scanPullRequestMock, rateLimitConfigs } = vi.hoisted(() => ({
  scanPullRequestMock: vi.fn(),
  rateLimitConfigs: [] as Array<{ keyPrefix: string; fallbackStrategy?: string }>,
}));

vi.mock("@/lib/armor/scanner", () => ({
  scanner: { scanPullRequest: scanPullRequestMock },
}));

vi.mock("@/lib/middleware/rate-limit", () => ({
  withRateLimit: <T>(handler: T, config: { keyPrefix: string; fallbackStrategy?: string }): T => {
    rateLimitConfigs.push(config);
    return handler;
  },
}));

vi.mock("@/lib/middleware/error-handler", () => {
  const AppError = class AppError extends Error {
    statusCode: number;
    constructor(msg: string, code = 400) {
      super(msg);
      this.statusCode = code;
    }
  };
  return {
    withErrorHandler:
      (fn: (...args: unknown[]) => unknown) =>
      async (...args: unknown[]) => {
        try {
          return await fn(...args);
        } catch (err: unknown) {
          const e = err as { statusCode?: number; message?: string };
          return {
            status: e.statusCode || 500,
            json: async () => ({ error: e.message }),
          };
        }
      },
    AppError,
  };
});

import { POST } from "./route";

function post(body: unknown): Promise<Response> {
  return POST(
    new NextRequest("http://localhost/api/cli/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  ) as unknown as Promise<Response>;
}

describe("POST /api/cli/scan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scanPullRequestMock.mockResolvedValue([]);
  });

  it("is rate limited under its own fail-closed bucket", () => {
    const config = rateLimitConfigs.find((c) => c.keyPrefix === "cli:scan");
    expect(config).toBeDefined();
    expect(config?.fallbackStrategy).toBe("fail-closed");
  });

  it("scans each file as a fully added patch", async () => {
    const res = await post({ files: [{ path: "src/app.ts", content: "a\nb" }] });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ findings: [] });
    expect(scanPullRequestMock).toHaveBeenCalledWith([
      { filename: "src/app.ts", patch: "@@ -0,0 +1,2 @@\n+a\n+b\n" },
    ]);
  });

  it.each([
    ["a file without content", { files: [{ path: "src/app.ts" }] }],
    ["a null entry", { files: [null] }],
    ["a string entry", { files: ["src/app.ts"] }],
    ["a non-string path", { files: [{ path: 42, content: "x" }] }],
    ["a non-string content", { files: [{ path: "src/app.ts", content: { nested: true } }] }],
    ["an empty path", { files: [{ path: "", content: "x" }] }],
  ])("rejects %s with 400 before scanning", async (_label, body) => {
    const res = await post(body);

    expect(res.status).toBe(400);
    expect(scanPullRequestMock).not.toHaveBeenCalled();
  });

  it("still rejects a missing or empty files array", async () => {
    expect((await post({})).status).toBe(400);
    expect((await post({ files: [] })).status).toBe(400);
    expect(scanPullRequestMock).not.toHaveBeenCalled();
  });
});
