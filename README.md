# supabase-rls-audit

Black-box security check for Supabase apps. Point it at your deployed app, or at your project URL
and public key, and it tells you what a stranger can read right now.

```bash
npx supabase-rls-audit https://your-app.lovable.app
```

It finds:

- **Tables anyone can read** with the public key, with row counts and the columns that look like
  personal data (emails, phones, addresses, tokens, government IDs, health data).
- **Service keys shipped to the browser.** A `service_role` or `sb_secret_` key in your front-end
  bundle bypasses Row Level Security completely.
- **Other secrets in the bundle**: Stripe, OpenAI, Anthropic, AWS, GitHub, Slack, Resend.
- **Public storage buckets**, and whether buckets can be listed anonymously.
- **Open signups and auto-confirm**, which make "only logged-in users" policies worthless.
- **An exposed schema**, so you know what an attacker can map.

Reads only. It never inserts, updates or deletes anything, never prints row contents, and never
stores what it sees.

## Why this exists

In 2025, a scan of 1,645 apps built with Lovable found 170 of them exposing personal data
(names, emails, API keys) to anyone with the public key, because Row Level Security was off or
wide open. The same pattern shows up in apps from Bolt, v0, Replit and hand-written projects:
the tool generates the tables, nobody turns on RLS, and the app ships. The public `anon` key is
in every browser that loads the app, so "nobody knows my project URL" is not protection.

This check takes two minutes and needs nothing but the URL.

## Install and run

Requires Node 20 or newer.

```bash
# Scan a deployed app. The Supabase URL and public key are picked up from the bundle.
npx supabase-rls-audit https://your-app.com

# Or give the project URL and the anon / publishable key directly.
npx supabase-rls-audit --url https://abcdefgh.supabase.co --key eyJhbGciOi...

# Both: scan the bundle for leaked secrets and audit the project.
npx supabase-rls-audit --app https://your-app.com --url https://abcdefgh.supabase.co --key ...

# Save a report you can send to whoever has to fix it.
npx supabase-rls-audit https://your-app.com --md report.md
npx supabase-rls-audit https://your-app.com --json > report.json
```

Options:

```
--tables a,b,c       Check only these tables
--skip-probe         When the schema is hidden, do not probe common table names
--max-tables <n>     Limit tables checked (default 200)
--timeout <ms>       Per-request timeout (default 10000)
--quiet              No progress output
--no-color           Plain output
```

Exit codes: `0` clean, `1` critical or high findings, `2` usage or network error. Put it in CI
and fail the build when a table leaks.

## What the output looks like

```
supabase-rls-audit v0.1.0
Target: https://abcdefgh.supabase.co   Key: anon (JWT, project abcdefgh)   App: https://your-app.com

Score: 10/100   Grade F

CRITICAL
  ✖ Table "users" is readable by anyone with the public key
      42 rows are visible without logging in. Columns: id, email, phone, full_name. Personal or secret data: email (email), phone (phone), full_name (name).
      Fix: alter table public."users" enable row level security; then add policies scoped to auth.uid(). ...
  ✖ service_role key shipped to the browser
      eyJhbGci…k2Vw (219 chars) found in https://your-app.com/assets/index-abc123.js. This key bypasses Row Level Security completely ...
      Fix: Rotate it now in Supabase > Project Settings > API. Move every use of it to a server ...

MEDIUM
  ▲ Public storage bucket: avatars
  ...

Tables (3 checked)
  users    EXPOSED    42 rows    email, phone, full_name
  posts    no rows    0 rows
  secrets  protected  HTTP 401 permission denied for table secrets
```

Run `npm run demo` in a clone of this repo to see it against a built-in fake project.

## How it works

1. **Schema**: PostgREST publishes an OpenAPI document at `/rest/v1/` that lists exposed tables,
   views, RPCs and columns. If it is hidden, the tool probes about fifty common table names
   (`users`, `orders`, `messages`, ...) unless you pass `--tables` or `--skip-probe`.
2. **Tables**: for each one, `GET /rest/v1/<table>?select=*&limit=5` with the public key, plus
   `Prefer: count=estimated` to learn how many rows are visible. Rows coming back means exposed.
   An empty array means RLS is working or the table is empty; from the outside those look the
   same, which is why there is an owner-side SQL report too.
3. **Bundle**: fetches the page, follows its `<script src>` and `modulepreload` tags (up to 30
   files, 5 MB each), and looks for Supabase JWTs (decoding the `role` claim), `sb_secret_` keys
   and common third-party secret formats.
4. **Auth and storage**: `/auth/v1/settings` for signups and providers; `/storage/v1/bucket` to
   see whether buckets are listable and which are public.

## What it does not check

- Inserts, updates and deletes. Testing those would mean writing to your database.
- What a logged-in user can see. Many leaks are "any authenticated user can read every row".
  Run the SQL report below to catch those.
- Edge Functions, your own backend, or anything behind your API.
- Apps whose bundle is loaded lazily and does not reference the Supabase client on the first
  page. Pass `--url` and `--key` directly in that case.

## The owner-side view

`sql/rls-report.sql` runs in Supabase > SQL Editor and shows, for every table in `public`:
whether RLS is enabled, every policy and its expression, tables with RLS on but no policies,
policies that are effectively `true` or only check `auth.role()`, grants to `anon` and
`authenticated`, public buckets, and `security definer` functions. Read-only.

## Fixing what it finds

- **Readable table**: `alter table public.<table> enable row level security;` then write
  policies that scope rows to the owner, for example
  `create policy "own rows" on public.<table> for select using (auth.uid() = user_id);`.
  A policy that only checks `auth.role() = 'authenticated'` is not a fix when signups are open.
- **Service key in the bundle**: rotate it in Project Settings > API, then move the code that
  used it to an Edge Function or your server. Only the anon/publishable key goes in a browser.
- **Public bucket with private files**: make it private and hand out signed URLs.
- **Open schema**: fine once RLS is right. Review each RPC, especially `security definer` ones.

## Responsible use

Only run this against projects you own or are explicitly authorized to test. It makes ordinary
read requests with the public key, the same ones a browser makes, but pointing it at someone
else's project without permission is not okay and may be illegal where you live.

## Need help?

I am Manuel, a software engineer. If this found something and you want it fixed properly,
RLS policies written, the service key moved server-side, the app stabilized and deployed with
tests, I do that work.

- Upwork: https://www.upwork.com/freelancers/~010fe827ccfbcb5d9a
- GitHub: https://github.com/ManuelDev1810
- Or open an issue here and I will take a look.

## License

MIT
