import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Local, on-disk cache of policy schemas so pre-commit hooks keep
 * working (in a reduced, non-AI capacity) when the user's connection
 * drops. Mirrors the policy shapes evaluated server-side by
 * `src/lib/armor/iq.ts`, kept intentionally minimal here.
 */

export interface CachedPolicy {
  id: string;
  name: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  enabled: boolean;
  /** Simple regex-based rule usable without a model call. */
  pattern: string;
  remediation: string;
}

export interface PolicyCache {
  fetchedAt: string;
  policies: CachedPolicy[];
}

const CACHE_DIR = join(homedir(), ".secureflow");
const CACHE_FILE = join(CACHE_DIR, "policy-cache.json");
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h

/** Built-in policies used on a completely fresh machine with no cache yet. */
export const FALLBACK_POLICIES: CachedPolicy[] = [
  {
    id: "hardcoded-secret",
    name: "Enforce No Hardcoded Secrets",
    severity: "HIGH",
    enabled: true,
    pattern:
      "(api[_-]?key|secret|password|token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-./+]{12,}['\"]",
    remediation: "Move the credential to an environment variable or secret manager.",
  },
  {
    id: "sql-injection",
    name: "Enforce Parameterized Queries",
    severity: "HIGH",
    enabled: true,
    pattern: "(SELECT|INSERT|UPDATE|DELETE).{0,80}\\$\\{",
    remediation: "Use parameterized queries instead of string interpolation.",
  },
  {
    id: "wildcard-cors",
    name: "Enforce Strict CORS Policies",
    severity: "MEDIUM",
    enabled: false,
    pattern: "Access-Control-Allow-Origin['\"]?\\s*[:=]\\s*['\"]\\*['\"]",
    remediation: "Restrict CORS to an explicit allow-list of origins.",
  },
];

export function readCache(): PolicyCache | null {
  if (!existsSync(CACHE_FILE)) return null;
  try {
    const raw = readFileSync(CACHE_FILE, "utf-8");
    return JSON.parse(raw) as PolicyCache;
  } catch {
    return null;
  }
}

export function writeCache(policies: CachedPolicy[]): void {
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true, mode: 0o700 });
  }
  const cache: PolicyCache = { fetchedAt: new Date().toISOString(), policies };
  writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2), { mode: 0o600 });
}

export function isCacheFresh(cache: PolicyCache): boolean {
  return Date.now() - new Date(cache.fetchedAt).getTime() < CACHE_TTL_MS;
}

/**
 * Returns the best available policy set without ever throwing:
 * fresh cache -> stale cache -> built-in fallback.
 */
export function getUsablePolicies(): { policies: CachedPolicy[]; stale: boolean } {
  const cache = readCache();
  if (!cache || cache.policies.length === 0) {
    return { policies: FALLBACK_POLICIES, stale: false };
  }
  return { policies: cache.policies, stale: !isCacheFresh(cache) };
}
