import type { Ctx, StorageInfo } from "../types.ts";

/** Listing buckets normally needs a policy; if the public key can do it, say so. */
export async function checkStorage(ctx: Ctx): Promise<StorageInfo> {
  const none: StorageInfo = { listed: false, buckets: [] };
  let res: Response;
  try {
    res = await ctx.get(`${ctx.url}/storage/v1/bucket`);
  } catch {
    return none;
  }
  if (!res.ok) return none;
  let j: unknown;
  try {
    j = await res.json();
  } catch {
    return none;
  }
  if (!Array.isArray(j)) return none;
  const buckets = j
    .map((b) => (b && typeof b === "object" ? (b as { id?: unknown; name?: unknown; public?: unknown }) : {}))
    .map((b) => ({
      name: String(b.name ?? b.id ?? "?"),
      public: b.public === true,
    }));
  return { listed: true, buckets };
}
