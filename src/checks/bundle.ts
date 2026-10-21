import type { BundleKey, BundleScan } from "../types.ts";
import { classifyKey, mask } from "../keys.ts";
import { fetchWithTimeout, readTextCapped } from "../http.ts";

const MAX_SCRIPTS = 30;
const MAX_BYTES = 5 * 1024 * 1024;

const OTHER_SECRETS: [RegExp, string][] = [
  [/\bsk_live_[A-Za-z0-9]{10,}/g, "Stripe secret key"],
  [/\bwhsec_[A-Za-z0-9]{10,}/g, "Stripe webhook secret"],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/g, "Anthropic API key"],
  [/\bsk-proj-[A-Za-z0-9_-]{20,}/g, "OpenAI API key"],
  [/\bsk-[A-Za-z0-9]{40,}\b/g, "OpenAI-style secret key"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "AWS access key id"],
  [/\bghp_[A-Za-z0-9]{30,}/g, "GitHub token"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, "Slack token"],
  [/\bre_[A-Za-z0-9]{20,}\b/g, "Resend API key"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, "Google API key (verify it is restricted; often fine client-side)"],
];

export interface ScanResult extends BundleScan {
  /** Discovered Supabase URL and anon/publishable key, so the audit can auto-target. */
  discovered: { url?: string; anonKey?: string };
}

export function emptyScan(): ScanResult {
  return { scriptsScanned: 0, supabaseUrls: [], keys: [], otherSecrets: [], discovered: {} };
}

/** Pure text scan, so it is testable without a network. */
export function scanText(body: string, where: string, into: ScanResult = emptyScan()): ScanResult {
  into.scriptsScanned += 1;
  for (const m of body.matchAll(/https:\/\/[a-z0-9-]+\.supabase\.(?:co|in)\b/g)) {
    if (!into.supabaseUrls.includes(m[0])) into.supabaseUrls.push(m[0]);
  }
  const seen = new Set([...into.keys, ...into.otherSecrets].map((k) => k.masked));
  const push = (list: BundleKey[], kind: string, raw: string) => {
    const masked = mask(raw);
    if (seen.has(masked)) return;
    seen.add(masked);
    list.push({ kind, masked, where });
  };
  for (const m of body.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g)) {
    const info = classifyKey(m[0]);
    if (info.iss !== "supabase") continue;
    if (info.kind === "anon" && !into.discovered.anonKey) into.discovered.anonKey = m[0];
    if (info.kind === "anon" || info.kind === "service_role") push(into.keys, info.kind, m[0]);
  }
  for (const m of body.matchAll(/\bsb_(publishable|secret)_[A-Za-z0-9_-]{10,}\b/g)) {
    const kind = m[1] === "secret" ? "secret" : "publishable";
    if (kind === "publishable" && !into.discovered.anonKey) into.discovered.anonKey = m[0];
    push(into.keys, kind, m[0]);
  }
  for (const [re, kind] of OTHER_SECRETS) {
    for (const m of body.matchAll(re)) push(into.otherSecrets, kind, m[0]);
  }
  if (!into.discovered.url && into.supabaseUrls[0]) into.discovered.url = into.supabaseUrls[0];
  return into;
}

function scriptUrls(html: string, base: string): string[] {
  const out: string[] = [];
  const add = (src: string) => {
    try {
      const u = new URL(src, base).toString();
      if (!out.includes(u)) out.push(u);
    } catch {
      /* ignore bad urls */
    }
  };
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) if (m[1]) add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\brel=["']modulepreload["'][^>]*\bhref=["']([^"']+)["']/gi)) if (m[1]) add(m[1]);
  return out.slice(0, MAX_SCRIPTS);
}

/** Fetch a deployed app, follow its script tags, and look for keys that should never be in a browser. */
export async function scanApp(
  appUrl: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  log: (m: string) => void,
): Promise<ScanResult> {
  const result = emptyScan();
  const res = await fetchWithTimeout(fetchImpl, appUrl, { headers: { Accept: "text/html,*/*" } }, timeoutMs);
  if (!res.ok) throw new Error(`could not load ${appUrl}: HTTP ${res.status}`);
  const html = await readTextCapped(res, MAX_BYTES);
  scanText(html, `${appUrl} (html)`, result);
  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    if (m[1] && m[1].trim()) scanText(m[1], `${appUrl} (inline script)`, result);
  }
  const urls = scriptUrls(html, res.url || appUrl);
  log(`scanning ${urls.length} script(s) referenced by ${appUrl}`);
  for (const u of urls) {
    try {
      const r = await fetchWithTimeout(fetchImpl, u, {}, timeoutMs);
      if (!r.ok) continue;
      scanText(await readTextCapped(r, MAX_BYTES), u, result);
    } catch (e) {
      log(`skip ${u}: ${(e as Error).message}`);
    }
  }
  return result;
}
