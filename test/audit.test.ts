import { test } from "node:test";
import assert from "node:assert/strict";
import { runAudit } from "../src/audit.ts";
import { classifyKey, mask } from "../src/keys.ts";
import { detectPii } from "../src/pii.ts";
import { scanText } from "../src/checks/bundle.ts";
import { scoreReport } from "../src/report.ts";
import { ANON_KEY, SERVICE_KEY, startMockServer } from "./mock-server.ts";

test("classifies Supabase keys", () => {
  assert.equal(classifyKey(ANON_KEY).kind, "anon");
  assert.equal(classifyKey(SERVICE_KEY).kind, "service_role");
  assert.equal(classifyKey("sb_secret_abcdefghijklmnop").kind, "secret");
  assert.equal(classifyKey("sb_publishable_abcdefghijklmnop").kind, "publishable");
  assert.equal(classifyKey("not-a-key").kind, "unknown");
  assert.match(mask(SERVICE_KEY), /…/);
  assert.ok(!mask(SERVICE_KEY).includes(SERVICE_KEY.slice(10, 40)));
});

test("flags personal and secret columns with table context", () => {
  const users = detectPii("users", ["id", "email", "phone_number", "created_at", "first_name", "last_login", "api_key"]).map((p) => p.column);
  assert.deepEqual(users, ["email", "phone_number", "first_name", "api_key"]);
  assert.deepEqual(detectPii("products", ["id", "name", "price", "location"]), []);
  assert.deepEqual(detectPii("messages", ["id", "content"]).map((p) => p.category), ["private content"]);
  assert.deepEqual(detectPii("events", ["id", "ip_address", "userAgent"]).map((p) => p.category), ["device/location", "device/location"]);
});

test("scans bundle text for keys and secrets", () => {
  const r = scanText(`x="${SERVICE_KEY}";y="sk_live_abcdefghijklmnop1234";z="https://abc.supabase.co";k="${ANON_KEY}"`, "inline");
  assert.ok(r.keys.some((k) => k.kind === "service_role"));
  assert.ok(r.keys.some((k) => k.kind === "anon"));
  assert.ok(r.otherSecrets.some((s) => s.kind.startsWith("Stripe")));
  assert.deepEqual(r.supabaseUrls, ["https://abc.supabase.co"]);
  assert.equal(r.discovered.url, "https://abc.supabase.co");
  assert.equal(r.discovered.anonKey, ANON_KEY);
});

test("refuses to run with a service_role key", async () => {
  await assert.rejects(runAudit({ url: "http://127.0.0.1:1", key: SERVICE_KEY }), /service_role/);
});

test("scores a clean report as A and a leaky one as F", () => {
  assert.deepEqual(scoreReport([]), { score: 100, grade: "A" });
  const leaky = scoreReport([
    { id: "service-key-in-bundle", severity: "critical", title: "", detail: "" },
    { id: "table-readable", severity: "critical", title: "", detail: "" },
  ]);
  assert.equal(leaky.score, 10);
  assert.equal(leaky.grade, "F");
});

test("full audit against a mock Supabase project", async () => {
  const srv = await startMockServer();
  try {
    const r = await runAudit({ url: srv.url, key: ANON_KEY, app: srv.url, timeoutMs: 3000 });
    const users = r.tables.find((t) => t.name === "users");
    assert.ok(users);
    assert.equal(users.status, "exposed");
    assert.equal(users.visibleRows, 42);
    assert.ok(users.pii.some((p) => p.column === "email"));
    assert.equal(r.tables.find((t) => t.name === "posts")?.status, "no-rows");
    assert.equal(r.tables.find((t) => t.name === "secrets")?.status, "protected");
    assert.deepEqual(r.rpcs, ["do_thing"]);
    assert.equal(r.schemaExposed, true);
    assert.equal(r.auth?.signupsOpen, true);
    assert.equal(r.auth?.autoconfirm, true);
    assert.deepEqual(r.auth?.providers, ["email", "google"]);
    assert.ok(r.storage?.buckets.some((b) => b.name === "avatars" && b.public));
    assert.ok(r.bundle?.keys.some((k) => k.kind === "service_role"));
    assert.ok(r.findings.some((f) => f.id === "service-key-in-bundle" && f.severity === "critical"));
    assert.ok(r.findings.some((f) => f.id === "table-readable" && f.target === "users" && f.severity === "critical"));
    assert.ok(r.findings.some((f) => f.id === "public-bucket"));
    assert.equal(r.grade, "F");
    assert.ok(r.score < 40, `score was ${r.score}`);
  } finally {
    await srv.close();
  }
});

test("falls back to probing when the schema is hidden", async () => {
  const srv = await startMockServer();
  try {
    const fetchImpl: typeof fetch = async (input, init) => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (u.endsWith("/rest/v1/")) return new Response("{}", { status: 401 });
      return fetch(input, init);
    };
    const r = await runAudit({ url: srv.url, key: ANON_KEY, fetchImpl, timeoutMs: 3000 });
    assert.equal(r.schemaExposed, false);
    assert.equal(r.tables.find((t) => t.name === "users")?.status, "exposed");
    assert.ok(r.tables.filter((t) => t.status === "not-found").length > 10);
  } finally {
    await srv.close();
  }
});
