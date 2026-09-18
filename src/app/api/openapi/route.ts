import { readFile } from "node:fs/promises";
import path from "node:path";
import { NextResponse } from "next/server";

/** Read from disk per request, so a redeploy is not needed to pick up an edit. */
export const dynamic = "force-dynamic";

/** Absolute path to the spec, which sits at the repository root. */
const SPEC_PATH = path.join(process.cwd(), "openapi.yaml");

/**
 * GET /api/openapi
 *
 * Serves the repository's `openapi.yaml` so `/docs/api-playground` can render
 * it. The playground reads the spec from here rather than from a copy under
 * `public/`, because a copy is exactly the kind of static duplicate that goes
 * stale the moment a route changes. One file, one source of truth.
 *
 * Public and unauthenticated, like the specification it serves. The middleware
 * puts it in the standard per-IP rate-limit bucket along with the other
 * non-exempt API routes.
 *
 * Swagger UI parses YAML itself, so the bytes are passed through untouched
 * rather than converted to JSON here.
 */
export async function GET() {
  try {
    const spec = await readFile(SPEC_PATH, "utf8");

    return new NextResponse(spec, {
      status: 200,
      headers: {
        "Content-Type": "application/yaml; charset=utf-8",
        // The spec only changes when the repository does, but a stale copy in a
        // developer's browser is confusing, so revalidate on every load.
        "Cache-Control": "no-cache",
      },
    });
  } catch {
    // Missing or unreadable means the deployment did not ship the file, not
    // that the caller did anything wrong.
    return NextResponse.json(
      { error: "The OpenAPI specification is unavailable." },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }
}
