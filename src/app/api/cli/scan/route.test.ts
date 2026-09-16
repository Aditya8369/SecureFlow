import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const { scanPullRequestMock } = vi.hoisted(() => ({
  scanPullRequestMock: vi.fn(),
}));

vi.mock("@/lib/armor/scanner", () => ({
  scanner: { scanPullRequest: scanPullRequestMock },
}));

vi.mock("@/lib/middleware/rate-limit", () => ({
  withRateLimit: <T>(handler: T): T => handler,
}));

import { POST } from "./route";

function post(body: unknown): Promise<Response> {
  return POST(
    new NextRequest("http://localhost/api/cli/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

describe("POST /api/cli/scan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scanPullRequestMock.mockResolvedValue([]);
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
