#!/usr/bin/env node
import { parseArgs } from "node:util";
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { runAudit } from "./audit.ts";
import { formatMarkdown, formatText } from "./report.ts";

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };
const HELP_URL = "https://github.com/ManuelDev1810/supabase-rls-audit#need-help";

const USAGE = `supabase-rls-audit v${version}
Black-box security check for Supabase apps. Reads only; never writes.

Usage
  supabase-rls-audit <https://your-app.com>
  supabase-rls-audit --url https://xxxx.supabase.co --key <anon or publishable key>
  supabase-rls-audit --app https://your-app.com --url ... --key ...

Options
  --app <url>          Deployed app to scan for embedded keys (auto-discovers URL and key)
  --url <url>          Supabase project URL
  --key <key>          Public anon / publishable key (never the service_role key)
  --tables a,b,c       Check only these tables (skips discovery and probing)
  --skip-probe         Do not probe common table names when the schema is hidden
  --max-tables <n>     Limit tables checked (default 200)
  --timeout <ms>       Per-request timeout (default 10000)
  --json               Print the report as JSON
  --md <file>          Also write a Markdown report
  --quiet              No progress output
  --no-color           Plain output
  -h, --help           This help
  -v, --version        Version

Exit codes: 0 clean, 1 critical or high findings, 2 usage or network error.
Only run this against projects you own or are authorized to test.`;

async function main(): Promise<void> {
  let parsed: ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>;
  try {
    parsed = parseArgs({ options: OPTIONS, allowPositionals: true });
  } catch (e) {
    console.error((e as Error).message);
    console.error("");
    console.error(USAGE);
    process.exit(2);
  }
  const { values, positionals } = parsed;
  if (values.help) { console.log(USAGE); return; }
  if (values.version) { console.log(version); return; }

  let url = values.url;
  let key = values.key;
  let app = values.app;
  for (const p of positionals) {
    if (!/^https?:\/\//.test(p)) continue;
    if (/\.supabase\.(co|in)\b/.test(p)) url ??= p;
    else app ??= p;
  }
  if (!url && !app) {
    console.error(USAGE);
    process.exit(2);
  }

  const quiet = values.quiet === true;
  const json = values.json === true;
  const color = values["no-color"] !== true && Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
  if (!quiet && !json) console.error("Only run this against projects you own or are authorized to test.\n");

  try {
    const report = await runAudit({
      url,
      key,
      app,
      tables: values.tables ? values.tables.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
      probe: values["skip-probe"] !== true,
      maxTables: values["max-tables"] ? Number(values["max-tables"]) : undefined,
      timeoutMs: values.timeout ? Number(values.timeout) : undefined,
      log: quiet || json ? undefined : (m) => console.error(`· ${m}`),
    });
    if (values.md) writeFileSync(values.md, formatMarkdown(report, { version, helpUrl: HELP_URL }));
    if (json) console.log(JSON.stringify(report, null, 2));
    else {
      console.log("");
      console.log(formatText(report, { color, version, helpUrl: HELP_URL }));
      if (values.md) console.log(`\nMarkdown report written to ${values.md}`);
    }
    const bad = report.findings.some((f) => f.severity === "critical" || f.severity === "high");
    process.exit(bad ? 1 : 0);
  } catch (e) {
    console.error(`error: ${(e as Error).message}`);
    process.exit(2);
  }
}

const OPTIONS = {
  app: { type: "string" },
  url: { type: "string" },
  key: { type: "string" },
  tables: { type: "string" },
  "skip-probe": { type: "boolean" },
  "max-tables": { type: "string" },
  timeout: { type: "string" },
  json: { type: "boolean" },
  md: { type: "string" },
  quiet: { type: "boolean" },
  "no-color": { type: "boolean" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

main();
