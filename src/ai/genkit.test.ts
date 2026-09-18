import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// genkit.ts builds the Genkit instance at import time. Both packages are mocked so the
// test only exercises how GROQ_MODEL is turned into model references.
vi.mock("genkit", () => ({ genkit: vi.fn(() => ({})) }));
vi.mock("genkitx-groq", () => ({
  groq: vi.fn(() => ({})),
  gptOssx20b: { name: "groq/openai/gpt-oss-20b" },
}));

async function loadGenkit(groqModel: string | undefined) {
  vi.resetModules();
  if (groqModel === undefined) {
    delete process.env.GROQ_MODEL;
  } else {
    process.env.GROQ_MODEL = groqModel;
  }
  return import("./genkit");
}

describe("toGenkitGroqModel", () => {
  it("adds the groq/ namespace to a bare Groq model id", async () => {
    const { toGenkitGroqModel } = await loadGenkit(undefined);
    expect(toGenkitGroqModel("openai/gpt-oss-20b")).toBe("groq/openai/gpt-oss-20b");
    expect(toGenkitGroqModel("llama-3.1-8b-instant")).toBe("groq/llama-3.1-8b-instant");
  });

  it("leaves an id that already has the namespace unchanged", async () => {
    const { toGenkitGroqModel } = await loadGenkit(undefined);
    expect(toGenkitGroqModel("groq/llama-3.3-70b-versatile")).toBe("groq/llama-3.3-70b-versatile");
    expect(toGenkitGroqModel("  groq/openai/gpt-oss-20b ")).toBe("groq/openai/gpt-oss-20b");
  });
});

describe("GROQ_MODEL handling", () => {
  const original = process.env.GROQ_MODEL;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    if (original === undefined) {
      delete process.env.GROQ_MODEL;
    } else {
      process.env.GROQ_MODEL = original;
    }
  });

  it("uses the .env.example value as a model Genkit can resolve", async () => {
    const { DEFAULT_SECURITY_CONFIG, getSecurityExplanationModelChain } =
      await loadGenkit("openai/gpt-oss-20b");

    expect(DEFAULT_SECURITY_CONFIG.modelName).toBe("groq/openai/gpt-oss-20b");
    expect(getSecurityExplanationModelChain()[0]).toBe("groq/openai/gpt-oss-20b");
  });

  it("passes the namespaced default model to the Genkit instance", async () => {
    await loadGenkit("llama-3.3-70b-versatile");
    const { genkit } = await import("genkit");

    expect(genkit).toHaveBeenCalledWith(
      expect.objectContaining({ model: "groq/llama-3.3-70b-versatile" }),
    );
  });

  it("keeps an already namespaced GROQ_MODEL as is", async () => {
    const { DEFAULT_SECURITY_CONFIG, getSecurityExplanationModelChain } = await loadGenkit(
      "groq/llama-3.3-70b-versatile",
    );

    expect(DEFAULT_SECURITY_CONFIG.modelName).toBe("groq/llama-3.3-70b-versatile");
    expect(getSecurityExplanationModelChain()[0]).toBe("groq/llama-3.3-70b-versatile");
  });

  it("falls back to the built-in defaults when GROQ_MODEL is unset or blank", async () => {
    for (const value of [undefined, "", "   "]) {
      const {
        DEFAULT_SECURITY_CONFIG,
        getSecurityExplanationModelChain,
        securityExplanationModel,
      } = await loadGenkit(value);

      expect(DEFAULT_SECURITY_CONFIG.modelName).toBe("groq/llama-3.1-8b-instant");
      expect(getSecurityExplanationModelChain()[0]).toBe(securityExplanationModel);
    }
  });
});
