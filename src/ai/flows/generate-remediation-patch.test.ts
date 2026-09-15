import { z } from "genkit";

import { ai, securityExplanationModel } from "@/ai/genkit";

// Use z.object() to create a standard Zod schema
const PatchOutputSchema = z.object({
  patchDiff: z.string().describe("The unified diff patch to fix the vulnerability."),
  explanation: z.string().describe("Brief explanation of the changes made."),
});

/**
 * Genkit AI Flow: Generate Remediation Patch
 * Analyzes a security finding and its surrounding code context to generate a unified diff patch.
 */

export const generateRemediationPatchFlow = ai.defineFlow(
  {
    name: "generateRemediationPatch",
    inputSchema: z.object({
      vulnerableCode: z.string(),
      findingDescription: z.string(),
      filePath: z.string(),
    }),
    outputSchema: PatchOutputSchema,
  },
  async (input) => {
    const prompt = `
You are an expert security engineer. Your task is to generate a unified diff patch to fix the following security vulnerability.

File: ${input.filePath}

Vulnerability: ${input.findingDescription}

Current Code:

\`\`\`
${input.vulnerableCode}
\`\`\`

Provide ONLY the unified diff patch that fixes this issue securely. Do not include markdown code blocks around the diff, just the raw diff text. Also provide a brief 1-sentence explanation of the fix.

`;

    try {
      const { output } = await ai.generate({
        model: securityExplanationModel,
        prompt: prompt,
        output: { schema: PatchOutputSchema, format: "json" },
      });

      if (output) {
        return output;
      }
    } catch (error) {
      console.warn("[REMEDIATION] AI provider unavailable, using static fallback:", error);
    }

    return {
      patchDiff: "",
      explanation:
        "The AI remediation service is temporarily unavailable. Please review the vulnerability manually and apply the appropriate secure remediation before merging.",
    };
  },
);
