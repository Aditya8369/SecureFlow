import "dotenv/config";
import { genkit } from "genkit";
import { groq, gpt0ssx20b } from "genkitx-groq";

/**
 * Configuration options for AI security flow initialization.
 * Pulls model name securely from environment variables with a safe fallback.
 */
export interface SecurityAIConfig {
  temperature?: number;
  maxOutputTokens?: number;
  modelName: string;
}

export const DEFAULT_SECURITY_CONFIG: SecurityAIConfig = {
  temperature: 0.2,
  maxOutputTokens: 1024,
  modelName: process.env.SECURITY_AI_MODEL || "groq/llama-3.1-8b-instant",
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

/**
 * Get ordered list of available models with fallback.
 */
export function getAvailableModels() {
  const customFallback = process.env.SECURITY_AI_FALLBACK;
  if (customFallback) {
    return [customFallback, ...availableGroqModels] as const;
  }
  return availableGroqModels;
}
