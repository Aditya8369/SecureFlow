import "dotenv/config";
import { genkit } from "genkit";
import { groq, gptOssx20b } from "genkitx-groq";

/**
 * Configuration options for AI security flow initialization.
 */
export interface SecurityAIConfig {
  temperature?: number;
  maxOutputTokens?: number;
  modelName: string;
}

/**
 * Genkit reference for a Groq model id.
 *
 * `GROQ_MODEL` holds the bare Groq id (`openai/gpt-oss-20b` in `.env.example`), which is
 * what the `groq-sdk` callers pass straight to the API. Genkit only knows the model under the
 * plugin's `groq/` namespace, and rejects the bare id with `NOT_FOUND: Model ... not found`.
 */
export function toGenkitGroqModel(modelId: string): string {
  const trimmed = modelId.trim();
  return trimmed.startsWith("groq/") ? trimmed : `groq/${trimmed}`;
}

/** `GROQ_MODEL` as a Genkit model reference, or undefined when it is unset or blank. */
function configuredGroqModel(): string | undefined {
  const modelId = process.env.GROQ_MODEL?.trim();
  return modelId ? toGenkitGroqModel(modelId) : undefined;
}

export const DEFAULT_SECURITY_CONFIG: SecurityAIConfig = {
  temperature: 0.2,
  maxOutputTokens: 1024,
  modelName: configuredGroqModel() ?? "groq/llama-3.1-8b-instant",
};

export const ai = genkit({
  plugins: [groq()],
  model: DEFAULT_SECURITY_CONFIG.modelName,
});

export const availableGroqModels = [
  "groq/llama-3.1-8b-instant",
  "groq/llama-3.1-70b-versatile",
  "groq/llama3-70b-8192",
  "groq/llama3-8b-8192",
  "groq/mixtral-8x7b-32768",
] as const;

export const securityExplanationModel = gptOssx20b;

export const securityExplanationFallbackModels = [
  "groq/llama-3.3-70b-versatile",
  "groq/llama-3.1-8b-instant",
  "groq/mixtral-8x7b-32768",
] as const;

export function getSecurityExplanationModelChain(): Array<typeof gptOssx20b | string> {
  const customFallback = configuredGroqModel();
  if (customFallback) {
    return [customFallback, securityExplanationModel, ...securityExplanationFallbackModels];
  }
  return [securityExplanationModel, ...securityExplanationFallbackModels];
}
