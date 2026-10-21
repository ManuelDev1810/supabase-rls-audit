export type KeyKind = "anon" | "service_role" | "publishable" | "secret" | "jwt-other" | "unknown";

export interface KeyInfo {
  kind: KeyKind;
  role?: string;
  iss?: string;
  ref?: string;
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) return null;
  try {
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    const obj: unknown = JSON.parse(json);
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Tell anon keys from service_role keys, and the new sb_publishable_/sb_secret_ format. */
export function classifyKey(key: string): KeyInfo {
  if (key.startsWith("sb_publishable_")) return { kind: "publishable" };
  if (key.startsWith("sb_secret_")) return { kind: "secret" };
  const p = decodeJwtPayload(key);
  if (!p) return { kind: "unknown" };
  const role = typeof p.role === "string" ? p.role : undefined;
  const iss = typeof p.iss === "string" ? p.iss : undefined;
  const ref = typeof p.ref === "string" ? p.ref : undefined;
  if (role === "anon") return { kind: "anon", role, iss, ref };
  if (role === "service_role") return { kind: "service_role", role, iss, ref };
  return { kind: "jwt-other", role, iss, ref };
}

export function describeKey(info: KeyInfo): string {
  switch (info.kind) {
    case "anon":
      return `anon (JWT${info.ref ? `, project ${info.ref}` : ""})`;
    case "service_role":
      return "service_role (JWT)";
    case "publishable":
      return "publishable (sb_publishable_)";
    case "secret":
      return "secret (sb_secret_)";
    case "jwt-other":
      return `JWT with role ${info.role ?? "?"}`;
    default:
      return "unknown format";
  }
}

/** Show enough of a secret to recognise it, never enough to use it. */
export function mask(secret: string): string {
  if (secret.length <= 12) return `${secret.slice(0, 3)}…`;
  return `${secret.slice(0, 8)}…${secret.slice(-4)} (${secret.length} chars)`;
}
