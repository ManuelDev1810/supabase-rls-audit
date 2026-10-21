export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable identifier, useful for filtering in CI. */
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** Table name, URL, or bucket the finding points at. */
  target?: string;
  fix?: string;
}

export interface PiiColumn {
  column: string;
  category: string;
}

export type TableStatus = "exposed" | "no-rows" | "protected" | "not-found" | "error";

export interface TableResult {
  name: string;
  status: TableStatus;
  httpStatus?: number;
  /** Rows visible to the public key, from Content-Range when the server reports it. */
  visibleRows?: number | null;
  columns: string[];
  pii: PiiColumn[];
  note?: string;
}

export interface BundleKey {
  kind: string;
  masked: string;
  where: string;
}

export interface BundleScan {
  scriptsScanned: number;
  supabaseUrls: string[];
  keys: BundleKey[];
  otherSecrets: BundleKey[];
}

export interface AuthInfo {
  signupsOpen: boolean;
  autoconfirm: boolean;
  providers: string[];
}

export interface StorageInfo {
  listed: boolean;
  buckets: { name: string; public: boolean }[];
}

export interface AuditOptions {
  /** Supabase project URL, e.g. https://abcd.supabase.co */
  url?: string;
  /** The public anon / publishable key. Never the service_role key. */
  key?: string;
  /** A deployed app URL to scan for embedded keys; the Supabase URL and key are auto-discovered from it when possible. */
  app?: string;
  /** Explicit table list; skips schema discovery and probing. */
  tables?: string[];
  /** When the schema is hidden and no tables are given, probe common table names. Default true. */
  probe?: boolean;
  maxTables?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  log?: (message: string) => void;
}

export interface AuditReport {
  generatedAt: string;
  supabaseUrl: string;
  keyType: string;
  app?: string;
  schemaExposed: boolean;
  tables: TableResult[];
  rpcs: string[];
  auth?: AuthInfo;
  storage?: StorageInfo;
  bundle?: BundleScan;
  findings: Finding[];
  score: number;
  grade: string;
}

export interface Ctx {
  url: string;
  key: string;
  get(url: string, headers?: Record<string, string>): Promise<Response>;
  log(message: string): void;
}
