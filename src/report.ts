import type { AuditReport, Finding, Severity } from "./types.ts";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

type Partial = Omit<AuditReport, "findings" | "score" | "grade">;

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export function buildFindings(r: Partial): Finding[] {
  const f: Finding[] = [];

  for (const t of r.tables) {
    if (t.status !== "exposed") continue;
    const pii = t.pii.map((p) => `${p.column} (${p.category})`);
    const rows = t.visibleRows == null ? "Rows are" : `${plural(t.visibleRows, "row")} are`;
    f.push({
      id: "table-readable",
      severity: pii.length ? "critical" : "high",
      target: t.name,
      title: `Table "${t.name}" is readable by anyone with the public key`,
      detail:
        `${rows} visible without logging in. Columns: ${t.columns.join(", ") || "unknown"}.` +
        (pii.length ? ` Personal or secret data: ${pii.join(", ")}.` : ""),
      fix:
        `alter table public."${t.name}" enable row level security; then add policies scoped to auth.uid(). ` +
        `If the table is meant to be public, make sure nothing personal lives in it.`,
    });
  }

  if (r.bundle) {
    for (const k of r.bundle.keys) {
      if (k.kind !== "service_role" && k.kind !== "secret") continue;
      f.push({
        id: "service-key-in-bundle",
        severity: "critical",
        target: k.where,
        title: `${k.kind === "secret" ? "Secret API key (sb_secret_)" : "service_role key"} shipped to the browser`,
        detail: `${k.masked} found in ${k.where}. This key bypasses Row Level Security completely: anyone who opens DevTools owns your database.`,
        fix: "Rotate it now in Supabase > Project Settings > API. Move every use of it to a server (Edge Function or your backend). Only the anon/publishable key belongs in a front-end.",
      });
    }
    for (const s of r.bundle.otherSecrets) {
      const soft = s.kind.includes("verify");
      f.push({
        id: "secret-in-bundle",
        severity: soft ? "medium" : "critical",
        target: s.where,
        title: `${s.kind} shipped to the browser`,
        detail: `${s.masked} found in ${s.where}.`,
        fix: soft
          ? "Check the key's restrictions in its provider console; restrict it to your domains and the APIs you use."
          : "Rotate the credential and move the call that uses it to a server.",
      });
    }
  }

  if (r.storage) {
    const pub = r.storage.buckets.filter((b) => b.public).map((b) => b.name);
    if (pub.length) {
      f.push({
        id: "public-bucket",
        severity: "medium",
        title: `Public storage bucket${pub.length > 1 ? "s" : ""}: ${pub.join(", ")}`,
        detail: "Every file in a public bucket is downloadable by URL. Fine for avatars and marketing images, wrong for user uploads, invoices, IDs, or anything a user expects to stay private.",
        fix: "Make the bucket private and serve files through signed URLs (storage.from(bucket).createSignedUrl).",
      });
    }
    if (r.storage.listed) {
      f.push({
        id: "buckets-listable",
        severity: "low",
        title: "Storage buckets can be listed with the public key",
        detail: `Anyone can enumerate your buckets: ${r.storage.buckets.map((b) => b.name).join(", ") || "none"}.`,
        fix: "Remove the select policy on storage.buckets for anon, or accept it if bucket names are not sensitive.",
      });
    }
  }

  if (r.schemaExposed) {
    f.push({
      id: "schema-exposed",
      severity: "low",
      title: "Database schema is visible to anyone",
      detail:
        `The PostgREST OpenAPI endpoint lists ${plural(r.tables.length, "table")}` +
        (r.rpcs.length ? ` and ${plural(r.rpcs.length, "RPC function")} (${r.rpcs.join(", ")})` : "") +
        ` with column names. Harmless when RLS is right; a map for attackers when it is not.`,
      fix: "Keep RLS tight on every exposed table. Review each RPC: a security definer function returns whatever it queries, regardless of RLS.",
    });
  }

  if (r.auth?.signupsOpen) {
    f.push({
      id: "signups-open",
      severity: "info",
      title: "Anyone can create an account",
      detail:
        `Email signups are enabled${r.auth.autoconfirm ? " with auto-confirm, so no email verification is needed" : ""}. ` +
        `Providers: ${r.auth.providers.join(", ") || "none"}.`,
      fix: "Expected for most apps. It means a policy like auth.role() = 'authenticated' is not protection: scope rows to auth.uid() or to a membership table.",
    });
  }

  const noRows = r.tables.filter((t) => t.status === "no-rows").map((t) => t.name);
  if (noRows.length) {
    f.push({
      id: "tables-no-rows",
      severity: "info",
      title: `${plural(noRows.length, "table")} returned no rows to the public key`,
      detail: `${noRows.join(", ")}. Either RLS is doing its job or the table is empty; from the outside the two look the same.`,
      fix: "Run sql/rls-report.sql in Supabase > SQL Editor to see RLS status and policies per table.",
    });
  }
  const prot = r.tables.filter((t) => t.status === "protected").map((t) => t.name);
  if (prot.length) {
    f.push({
      id: "tables-protected",
      severity: "info",
      title: `${plural(prot.length, "table")} explicitly denied the public key`,
      detail: prot.join(", "),
      fix: "Good. Nothing to do.",
    });
  }

  f.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  return f;
}

export function scoreReport(findings: Finding[]): { score: number; grade: string } {
  let s = 100;
  for (const f of findings) {
    switch (f.id) {
      case "table-readable": s -= f.severity === "critical" ? 30 : 15; break;
      case "service-key-in-bundle": s -= 60; break;
      case "secret-in-bundle": s -= f.severity === "critical" ? 25 : 5; break;
      case "public-bucket": s -= 10; break;
      case "buckets-listable": s -= 3; break;
      case "schema-exposed": s -= 3; break;
      case "signups-open": s -= 2; break;
      default: break;
    }
  }
  s = Math.max(0, Math.min(100, s));
  const grade = s >= 90 ? "A" : s >= 75 ? "B" : s >= 60 ? "C" : s >= 40 ? "D" : "F";
  return { score: s, grade };
}

export interface FormatOptions {
  color: boolean;
  version: string;
  helpUrl: string;
}

function painter(enabled: boolean) {
  const wrap = (open: string, close: string) => (s: string) => (enabled ? `\u001b[${open}m${s}\u001b[${close}m` : s);
  return {
    bold: wrap("1", "22"),
    dim: wrap("2", "22"),
    red: wrap("31", "39"),
    green: wrap("32", "39"),
    yellow: wrap("33", "39"),
    blue: wrap("34", "39"),
  };
}

const SYMBOL: Record<Severity, string> = { critical: "✖", high: "✖", medium: "▲", low: "•", info: "·" };

export function formatText(r: AuditReport, o: FormatOptions): string {
  const c = painter(o.color);
  const sevPaint: Record<Severity, (s: string) => string> = {
    critical: c.red, high: c.red, medium: c.yellow, low: c.blue, info: c.dim,
  };
  const L: string[] = [];
  L.push(c.bold(`supabase-rls-audit v${o.version}`));
  L.push(`Target: ${r.supabaseUrl}   Key: ${r.keyType}${r.app ? `   App: ${r.app}` : ""}`);
  L.push("");
  const gradePaint = r.grade === "A" || r.grade === "B" ? c.green : r.grade === "C" ? c.yellow : c.red;
  L.push(`${c.bold("Score:")} ${gradePaint(`${r.score}/100   Grade ${r.grade}`)}`);
  L.push("");
  for (const sev of SEVERITY_ORDER) {
    const list = r.findings.filter((f) => f.severity === sev);
    if (!list.length) continue;
    L.push(sevPaint[sev](c.bold(sev.toUpperCase())));
    for (const f of list) {
      L.push(`  ${sevPaint[sev](SYMBOL[sev])} ${f.title}`);
      L.push(`      ${c.dim(f.detail)}`);
      if (f.fix) L.push(`      ${c.dim(`Fix: ${f.fix}`)}`);
    }
    L.push("");
  }
  const shown = r.tables.filter((t) => t.status !== "not-found");
  if (shown.length) {
    L.push(c.bold(`Tables (${shown.length} checked)`));
    const w = Math.max(5, ...shown.map((t) => t.name.length));
    for (const t of shown) {
      const status =
        t.status === "exposed" ? c.red("EXPOSED  ")
        : t.status === "no-rows" ? c.green("no rows  ")
        : t.status === "protected" ? c.green("protected")
        : c.yellow(t.status.padEnd(9));
      const rows = t.visibleRows == null ? "" : `${t.visibleRows} rows`;
      const pii = t.pii.length ? c.red(t.pii.map((p) => p.column).join(", ")) : "";
      const note = t.status === "protected" || t.status === "error" ? c.dim(`HTTP ${t.httpStatus ?? "?"}${t.note ? ` ${t.note}` : ""}`) : "";
      L.push(`  ${t.name.padEnd(w)}  ${status}  ${rows.padEnd(10)} ${pii}${note}`);
    }
    const probedMissing = r.tables.length - shown.length;
    if (probedMissing) L.push(c.dim(`  (${probedMissing} probed names did not exist)`));
    L.push("");
  }
  if (r.bundle) {
    L.push(c.bold("Front-end bundle"));
    L.push(
      `  ${plural(r.bundle.scriptsScanned, "source")} scanned. Supabase URLs: ${r.bundle.supabaseUrls.join(", ") || "none"}. ` +
      `Keys: ${r.bundle.keys.map((k) => k.kind).join(", ") || "none"}. Other secrets: ${r.bundle.otherSecrets.length}.`,
    );
    L.push("");
  }
  L.push(c.dim("Not checked: inserts, updates, deletes; what logged-in users can see; Edge Functions; your own backend."));
  L.push(c.dim("Owner view: run sql/rls-report.sql in Supabase > SQL Editor."));
  L.push("");
  L.push(`Need it fixed properly? ${o.helpUrl}`);
  return L.join("\n");
}

export function formatMarkdown(r: AuditReport, o: Pick<FormatOptions, "version" | "helpUrl">): string {
  const L: string[] = [];
  L.push(`# Supabase RLS audit`);
  L.push("");
  L.push(`Generated ${r.generatedAt} by supabase-rls-audit v${o.version}`);
  L.push("");
  L.push(`- Target: \`${r.supabaseUrl}\``);
  L.push(`- Key: ${r.keyType}`);
  if (r.app) L.push(`- App: ${r.app}`);
  L.push(`- **Score: ${r.score}/100, grade ${r.grade}**`);
  L.push("");
  for (const sev of SEVERITY_ORDER) {
    const list = r.findings.filter((f) => f.severity === sev);
    if (!list.length) continue;
    L.push(`## ${sev[0]?.toUpperCase()}${sev.slice(1)}`);
    L.push("");
    for (const f of list) {
      L.push(`### ${f.title}`);
      L.push("");
      L.push(f.detail);
      if (f.fix) {
        L.push("");
        L.push(`**Fix:** ${f.fix}`);
      }
      L.push("");
    }
  }
  const shown = r.tables.filter((t) => t.status !== "not-found");
  if (shown.length) {
    L.push("## Tables");
    L.push("");
    L.push("| Table | Status | Visible rows | Personal data |");
    L.push("|---|---|---|---|");
    for (const t of shown) {
      L.push(`| ${t.name} | ${t.status} | ${t.visibleRows ?? ""} | ${t.pii.map((p) => p.column).join(", ")} |`);
    }
    L.push("");
  }
  L.push("## Not checked");
  L.push("");
  L.push("Inserts, updates and deletes; what logged-in users can see; Edge Functions; your own backend. Run `sql/rls-report.sql` in the SQL editor for the owner-side view.");
  L.push("");
  L.push(`Need it fixed properly? ${o.helpUrl}`);
  L.push("");
  return L.join("\n");
}
