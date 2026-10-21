import type { Ctx, TableResult } from "../types.ts";
import { detectPii } from "../pii.ts";

/** Probed when the schema is hidden and no table list was given. */
export const COMMON_TABLES = [
  "users", "profiles", "user_profiles", "accounts", "customers", "clients", "members", "employees",
  "patients", "contacts", "leads", "subscribers", "waitlist", "newsletter",
  "orders", "order_items", "products", "carts", "cart_items", "payments", "transactions", "invoices",
  "subscriptions", "coupons", "addresses",
  "messages", "chats", "conversations", "posts", "comments", "reviews", "feedback", "notifications",
  "bookings", "appointments", "reservations", "events", "tasks", "projects", "teams", "organizations",
  "documents", "files", "uploads", "notes", "settings", "sessions", "tokens", "api_keys", "logs",
  "prompts", "generations",
];

function parseTotal(contentRange: string | null): number | null {
  if (!contentRange) return null;
  const m = /\/(\d+|\*)\s*$/.exec(contentRange);
  if (!m || !m[1] || m[1] === "*") return null;
  return Number(m[1]);
}

/** Ask PostgREST for a few rows as the public key would. Reads only; never writes. */
export async function checkTable(ctx: Ctx, name: string, knownColumns: string[]): Promise<TableResult> {
  const base: TableResult = { name, status: "error", columns: knownColumns, pii: [] };
  const url = `${ctx.url}/rest/v1/${encodeURIComponent(name)}?select=*&limit=5`;
  let res: Response;
  try {
    res = await ctx.get(url, { Prefer: "count=estimated" });
  } catch (e) {
    return { ...base, note: (e as Error).message };
  }
  const httpStatus = res.status;
  if (httpStatus === 404) return { ...base, status: "not-found", httpStatus };
  if (httpStatus === 401 || httpStatus === 403) return { ...base, status: "protected", httpStatus };

  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (httpStatus >= 400) {
    const err = (body ?? {}) as { code?: string; message?: string };
    if (err.code === "42501" || /permission denied/i.test(err.message ?? "")) {
      return { ...base, status: "protected", httpStatus, note: err.message };
    }
    if (err.code === "42P01" || /does not exist|not find the table/i.test(err.message ?? "")) {
      return { ...base, status: "not-found", httpStatus };
    }
    return { ...base, httpStatus, note: err.message ?? `HTTP ${httpStatus}` };
  }
  if (!Array.isArray(body)) return { ...base, httpStatus, note: "unexpected response shape" };

  const total = parseTotal(res.headers.get("content-range"));
  const first = body[0];
  const columns = first && typeof first === "object" ? Object.keys(first as object) : knownColumns;
  if (body.length > 0) {
    return {
      name,
      status: "exposed",
      httpStatus,
      visibleRows: total ?? body.length,
      columns,
      pii: detectPii(name, columns),
    };
  }
  return { name, status: "no-rows", httpStatus, visibleRows: total ?? 0, columns, pii: [] };
}
