import type { Ctx } from "../types.ts";

export interface SchemaInfo {
  exposed: boolean;
  httpStatus?: number;
  tables: { name: string; columns: string[] }[];
  rpcs: string[];
}

/** PostgREST publishes an OpenAPI document at /rest/v1/ listing every exposed table, view and RPC. */
export async function discoverSchema(ctx: Ctx): Promise<SchemaInfo> {
  const empty: SchemaInfo = { exposed: false, tables: [], rpcs: [] };
  let res: Response;
  try {
    res = await ctx.get(`${ctx.url}/rest/v1/`, { Accept: "application/openapi+json, application/json" });
  } catch (e) {
    ctx.log(`schema discovery failed: ${(e as Error).message}`);
    return empty;
  }
  if (!res.ok) return { ...empty, httpStatus: res.status };
  let spec: unknown;
  try {
    spec = await res.json();
  } catch {
    return { ...empty, httpStatus: res.status };
  }
  if (!spec || typeof spec !== "object") return { ...empty, httpStatus: res.status };
  const s = spec as {
    definitions?: Record<string, unknown>;
    components?: { schemas?: Record<string, unknown> };
    paths?: Record<string, unknown>;
  };
  const defs = s.definitions ?? s.components?.schemas ?? {};
  const tables = new Map<string, string[]>();
  for (const [name, def] of Object.entries(defs)) {
    const props =
      def && typeof def === "object" && "properties" in def && def.properties && typeof def.properties === "object"
        ? Object.keys(def.properties as Record<string, unknown>)
        : [];
    tables.set(name, props);
  }
  const rpcs: string[] = [];
  for (const p of Object.keys(s.paths ?? {})) {
    if (p.startsWith("/rpc/")) rpcs.push(p.slice(5));
    else if (p.length > 1) {
      const name = decodeURIComponent(p.slice(1));
      if (!tables.has(name)) tables.set(name, []);
    }
  }
  return {
    exposed: tables.size > 0 || rpcs.length > 0,
    httpStatus: res.status,
    tables: [...tables].map(([name, columns]) => ({ name, columns })),
    rpcs: rpcs.sort(),
  };
}
