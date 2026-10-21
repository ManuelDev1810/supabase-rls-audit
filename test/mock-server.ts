import http from "node:http";

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
export function makeJwt(payload: object): string {
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;
}
export const ANON_KEY = makeJwt({ iss: "supabase", ref: "mockproject", role: "anon", iat: 1, exp: 2 });
export const SERVICE_KEY = makeJwt({ iss: "supabase", ref: "mockproject", role: "service_role", iat: 1, exp: 2 });

const OPENAPI = {
  swagger: "2.0",
  paths: { "/": {}, "/users": {}, "/posts": {}, "/secrets": {}, "/rpc/do_thing": {} },
  definitions: {
    users: { properties: { id: {}, email: {}, phone: {}, full_name: {} } },
    posts: { properties: { id: {}, title: {} } },
    secrets: { properties: { id: {}, token: {} } },
  },
};

/** A tiny fake of PostgREST + GoTrue + Storage with one leaky table, one safe table and one denied table. */
export async function startMockServer(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://localhost");
    const json = (code: number, body: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(code, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(body));
    };
    switch (u.pathname) {
      case "/rest/v1/":
        return json(200, OPENAPI);
      case "/rest/v1/users":
        return json(200, [{ id: 1, email: "a@b.c", phone: "809", full_name: "A" }], { "content-range": "0-0/42" });
      case "/rest/v1/posts":
        return json(200, [], { "content-range": "*/0" });
      case "/rest/v1/secrets":
        return json(401, { code: "42501", message: "permission denied for table secrets" });
      case "/auth/v1/settings":
        return json(200, { external: { email: true, google: true, github: false }, disable_signup: false, mailer_autoconfirm: true });
      case "/storage/v1/bucket":
        return json(200, [{ id: "avatars", name: "avatars", public: true }, { id: "private-docs", name: "private-docs", public: false }]);
      case "/":
        res.writeHead(200, { "content-type": "text/html" });
        return res.end(`<!doctype html><html><head><script type="module" src="/assets/index.js"></script></head><body>demo</body></html>`);
      case "/assets/index.js":
        res.writeHead(200, { "content-type": "text/javascript" });
        return res.end(
          `const u="https://mockproject.supabase.co";const k="${ANON_KEY}";const s="${SERVICE_KEY}";const st="sk_live_abcdefghijklmnop1234";`,
        );
      default:
        return json(404, { message: "not found" });
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
