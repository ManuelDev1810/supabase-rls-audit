-- supabase-rls-audit: owner-side report.
-- Run in Supabase Dashboard > SQL Editor. Read-only; changes nothing.
-- The CLI shows what an anonymous visitor sees. This shows why.

-- 1. Tables in the public schema and whether RLS is on.
--    rls_enabled = false on a table that holds user data is the classic hole.
select n.nspname  as schema,
       c.relname  as "table",
       c.relrowsecurity   as rls_enabled,
       c.relforcerowsecurity as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname = 'public'
order by c.relrowsecurity, c.relname;

-- 2. Every policy, so you can read what each one actually allows.
select schemaname, tablename, policyname, permissive, roles, cmd, qual as using_expr, with_check
from pg_policies
where schemaname = 'public'
order by tablename, policyname;

-- 3. RLS on but zero policies: everything is blocked. Usually "I enabled RLS and the app broke".
select c.relname as "table"
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join pg_policies p on p.tablename = c.relname and p.schemaname = n.nspname
where n.nspname = 'public'
  and c.relkind in ('r', 'p')
  and c.relrowsecurity
  and p.policyname is null;

-- 4. Policies that are effectively open: "true", or only checking that the user is logged in.
--    Anyone can sign up, so auth.role() = 'authenticated' protects nothing.
select tablename, policyname, roles, cmd, qual as using_expr, with_check
from pg_policies
where schemaname = 'public'
  and (
    coalesce(qual, '') in ('true', '(true)')
    or coalesce(with_check, '') in ('true', '(true)')
    or coalesce(qual, '') ilike '%auth.role()%'
    or coalesce(with_check, '') ilike '%auth.role()%'
  );

-- 5. What the anon and authenticated roles are granted on each table.
select table_name, grantee, string_agg(privilege_type, ', ' order by privilege_type) as privileges
from information_schema.role_table_grants
where table_schema = 'public'
  and grantee in ('anon', 'authenticated')
group by table_name, grantee
order by table_name, grantee;

-- 6. Storage: public buckets and the policies on objects.
select id, name, public, created_at from storage.buckets order by public desc, name;

select policyname, cmd, roles, qual as using_expr, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by policyname;

-- 7. Security definer functions exposed through the API run with the owner's rights, not the caller's.
select p.proname as function, pg_get_function_identity_arguments(p.oid) as args
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prosecdef
order by p.proname;
