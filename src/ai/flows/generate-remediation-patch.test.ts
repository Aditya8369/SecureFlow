import { describe, it, expect, vi, beforeEach } from "vitest";

const { mockGenerate } = vi.hoisted(() => ({ mockGenerate: vi.fn() }));

// defineFlow returns the handler itself, so the tests call the flow body directly
// without starting Genkit or loading the Groq plugin.
vi.mock("@/ai/genkit", () => ({
  ai: {
    defineFlow: (_config: unknown, handler: unknown) => handler,
    generate: (...args: unknown[]) => mockGenerate(...args),
  },
  securityExplanationModel: "mock-security-model",
}));

import { generateRemediationPatchFlow } from "./generate-remediation-patch";

const input = {
  vulnerableCode: 'db.query("SELECT * FROM users WHERE id=" + id)',
  findingDescription: "SQL injection via string concatenation",
  filePath: "src/db.ts",
};

describe("generateRemediationPatchFlow", () => {
  beforeEach(() => {
    mockGenerate.mockReset();
  });

  it("returns the model's patch and sends the finding context in the prompt", async () => {
    const output = { patchDiff: "--- a/src/db.ts\n+++ b/src/db.ts", explanation: "Use params." };
    mockGenerate.mockResolvedValue({ output });

    await expect(generateRemediationPatchFlow(input)).resolves.toEqual(output);

    expect(mockGenerate).toHaveBeenCalledTimes(1);
    const [request] = mockGenerate.mock.calls[0];
    expect(request.model).toBe("mock-security-model");
    expect(request.output).toMatchObject({ format: "json" });
    expect(request.prompt).toContain("File: src/db.ts");
    expect(request.prompt).toContain("Vulnerability: SQL injection via string concatenation");
    expect(request.prompt).toContain(input.vulnerableCode);
  });

  it("falls back to static guidance when the AI provider throws", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    mockGenerate.mockRejectedValue(new Error("Request timed out"));

    const result = await generateRemediationPatchFlow(input);

    expect(result.patchDiff).toBe("");
    expect(result.explanation).toMatch(/temporarily unavailable/);
  });

  it("falls back to static guidance when the model returns no output", async () => {
    mockGenerate.mockResolvedValue({ output: null });

    const result = await generateRemediationPatchFlow(input);

    expect(result.patchDiff).toBe("");
    expect(result.explanation).toMatch(/temporarily unavailable/);
  });
});
