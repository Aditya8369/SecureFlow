import { describe, expect, it, vi } from "vitest";

// genkit.ts builds the Genkit instance at import time. Both packages are mocked so the
// test only exercises how GROQ_MODEL is turned into model references.
vi.mock("genkit", () => ({ genkit: vi.fn(() => ({})) }));
vi.mock("genkitx-groq", () => ({
  groq: vi.fn(() => ({})),
  gptOssx20b: { name: "groq/openai/gpt-oss-20b" },
}));

async function loadGenkit() {
  return import("./genkit");
}

describe("toGenkitGroqModel", () => {
  it("adds the groq/ namespace to a bare Groq model id", async () => {
    const { toGenkitGroqModel } = await loadGenkit();
    expect(toGenkitGroqModel("openai/gpt-oss-20b")).toBe("groq/openai/gpt-oss-20b");
    expect(toGenkitGroqModel("llama-3.1-8b-instant")).toBe("groq/llama-3.1-8b-instant");
  });

  it("leaves an id that already has the namespace unchanged", async () => {
    const { toGenkitGroqModel } = await loadGenkit();
    expect(toGenkitGroqModel("groq/llama-3.3-70b-versatile")).toBe("groq/llama-3.3-70b-versatile");
    expect(toGenkitGroqModel("  groq/openai/gpt-oss-20b ")).toBe("groq/openai/gpt-oss-20b");
  });
});
