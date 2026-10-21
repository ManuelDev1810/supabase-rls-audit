import type { AuthInfo, Ctx } from "../types.ts";

/** GoTrue exposes its public settings; they tell us whether anyone can sign up. */
export async function checkAuth(ctx: Ctx): Promise<AuthInfo | undefined> {
  let res: Response;
  try {
    res = await ctx.get(`${ctx.url}/auth/v1/settings`);
  } catch {
    return undefined;
  }
  if (!res.ok) return undefined;
  let j: unknown;
  try {
    j = await res.json();
  } catch {
    return undefined;
  }
  if (!j || typeof j !== "object") return undefined;
  const s = j as { external?: Record<string, unknown>; disable_signup?: unknown; mailer_autoconfirm?: unknown };
  const providers = Object.entries(s.external ?? {})
    .filter(([, v]) => v === true)
    .map(([k]) => k)
    .sort();
  return {
    signupsOpen: s.disable_signup === false,
    autoconfirm: s.mailer_autoconfirm === true,
    providers,
  };
}
