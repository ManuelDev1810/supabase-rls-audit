import type { AuditOptions, AuditReport, Ctx } from "./types.ts";
import { classifyKey, describeKey } from "./keys.ts";
import { fetchWithTimeout, pool } from "./http.ts";
import { discoverSchema } from "./checks/openapi.ts";
import { COMMON_TABLES, checkTable } from "./checks/tables.ts";
import { checkAuth } from "./checks/auth.ts";
import { checkStorage } from "./checks/storage.ts";
import { scanApp } from "./checks/bundle.ts";
import { buildFindings, scoreReport } from "./report.ts";

export type { AuditOptions, AuditReport, Finding, TableResult } from "./types.ts";
export { formatText, formatMarkdown } from "./report.ts";

/**
 * Black-box audit of a Supabase project as an anonymous visitor would see it.
 * Reads only. Never inserts, updates or deletes anything.
 */
export async function runAudit(opts: AuditOptions): Promise<AuditReport> {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const log = opts.log ?? (() => {});
  const maxTables = opts.maxTables ?? 200;

  let url = opts.url?.trim().replace(/\/+$/, "");
  let key = opts.key?.trim();
  let bundle: Awaited<ReturnType<typeof scanApp>> | undefined;

  if (opts.app) {
    log(`loading ${opts.app}`);
    bundle = await scanApp(opts.app, fetchImpl, timeoutMs, log);
    if (!url && bundle.discovered.url) {
      url = bundle.discovered.url;
      log(`found Supabase URL in the app: ${url}`);
    }
    if (!key && bundle.discovered.anonKey) {
      key = bundle.discovered.anonKey;
      log("found the public key in the app");
    }
  }
  if (!url || !key) {
    throw new Error(
      opts.app
        ? "could not find a Supabase URL and public key in that app; pass --url and --key explicitly"
        : "pass --url and --key (the anon/publishable key), or --app with a deployed app URL",
    );
  }
  if (!/^https?:\/\//.test(url)) throw new Error(`invalid Supabase URL: ${url}`);

  const keyInfo = classifyKey(key);
  if (keyInfo.kind === "service_role" || keyInfo.kind === "secret") {
    throw new Error(
      "that is a service_role / secret key. It bypasses RLS, so the results would be meaningless and you would be pasting your master key into a tool. Use the anon or publishable key.",
    );
  }

  const ctx: Ctx = {
    url,
    key,
    log,
    get: (u, headers = {}) =>
      fetchWithTimeout(fetchImpl, u, { headers: { apikey: key as string, Authorization: `Bearer ${key}`, ...headers } }, timeoutMs),
  };

  log("discovering schema");
  const schema = await discoverSchema(ctx);
  let candidates: { name: string; columns: string[] }[];
  if (opts.tables?.length) {
    candidates = opts.tables.map((name) => ({ name, columns: [] }));
  } else if (schema.exposed) {
    candidates = schema.tables;
  } else if (opts.probe !== false) {
    log("schema hidden; probing common table names");
    candidates = COMMON_TABLES.map((name) => ({ name, columns: [] }));
  } else {
    candidates = [];
  }
  candidates = candidates.slice(0, maxTables);

  log(`checking ${candidates.length} table(s)`);
  const tables = await pool(candidates, 5, (t) => checkTable(ctx, t.name, t.columns));
  const [auth, storage] = await Promise.all([checkAuth(ctx), checkStorage(ctx)]);

  const partial = {
    generatedAt: new Date().toISOString(),
    supabaseUrl: url,
    keyType: describeKey(keyInfo),
    app: opts.app,
    schemaExposed: schema.exposed,
    tables,
    rpcs: schema.rpcs,
    auth,
    storage,
    bundle: bundle
      ? { scriptsScanned: bundle.scriptsScanned, supabaseUrls: bundle.supabaseUrls, keys: bundle.keys, otherSecrets: bundle.otherSecrets }
      : undefined,
  };
  const findings = buildFindings(partial);
  const { score, grade } = scoreReport(findings);
  return { ...partial, findings, score, grade };
}
