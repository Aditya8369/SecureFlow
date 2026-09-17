import { describe, it, expect, vi } from "vitest";

const { rateLimitConfigs } = vi.hoisted(() => ({
  rateLimitConfigs: [] as Array<{ keyPrefix: string; fallbackStrategy?: string }>,
}));

vi.mock("@/lib/middleware/rate-limit", () => ({
  withRateLimit: <T>(handler: T, config: { keyPrefix: string; fallbackStrategy?: string }): T => {
    rateLimitConfigs.push(config);
    return handler;
  },
}));

vi.mock("@/lib/middleware/error-handler", () => ({
  withErrorHandler: (fn: unknown) => fn,
  AppError: class AppError extends Error {},
}));

vi.mock("@/lib/armor/scanner", () => ({
  scanner: {
    scanPullRequest: vi.fn(),
  },
}));

// Import after mocks so the route's `withRateLimit` call executes the mock.
import "@/app/api/cli/scan/route";

describe("POST /api/cli/scan", () => {
  it("is rate limited under its own fail-closed bucket", () => {
    const config = rateLimitConfigs.find((c) => c.keyPrefix === "cli:scan");
    expect(config).toBeDefined();
    expect(config?.fallbackStrategy).toBe("fail-closed");
  });
});
