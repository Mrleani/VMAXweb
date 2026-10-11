-- VMAXweb core schema (Supabase / PostgreSQL)
-- Run via `supabase db push` or the SQL editor.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- profiles: one row per auth user, holds plan + billing linkage
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
    id uuid primary key references auth.users (id) on delete cascade,
    email text,
    plan text not null default 'free' check (plan in ('free', 'pro')),
    stripe_customer_id text,
    created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "profiles_select_own"
    on public.profiles for select
    using (auth.uid() = id);

create policy "profiles_update_own"
    on public.profiles for update
    using (auth.uid() = id);

-- Auto-create a profile whenever a new auth user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.profiles (id, email)
    values (new.id, new.email)
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- targets: domains the user scans (unique per user + host)
-- ---------------------------------------------------------------------------
create table if not exists public.targets (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references public.profiles (id) on delete cascade,
    url text not null,
    host text not null,
    verified_at timestamptz,
    created_at timestamptz not null default now(),
    unique (user_id, host)
);

create index if not exists targets_user_idx on public.targets (user_id);

alter table public.targets enable row level security;

create policy "targets_owner_all"
    on public.targets for all
    using (auth.uid() = user_id)
    with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- scans: one audit run
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references public.profiles (id) on delete cascade,
    target_id uuid not null references public.targets (id) on delete cascade,
    status text not null default 'completed',
    score int not null default 0,
    grade text,
    grade_label text,
    trigger text not null default 'manual' check (trigger in ('manual', 'scheduled')),
    engine_version text,
    started_at timestamptz not null,
    finished_at timestamptz not null,
    duration_ms int not null default 0,
    created_at timestamptz not null default now()
);

create index if not exists scans_user_finished_idx
    on public.scans (user_id, finished_at desc);
create index if not exists scans_target_idx on public.scans (target_id);

alter table public.scans enable row level security;

create policy "scans_owner_all"
    on public.scans for all
    using (auth.uid() = user_id)
    with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- findings: individual audit results belonging to a scan
-- ---------------------------------------------------------------------------
create table if not exists public.findings (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null references public.scans (id) on delete cascade,
    finding_key text not null,
    module text not null,
    name text not null,
    severity text not null check (severity in ('critical', 'warning', 'passed', 'info')),
    status text,
    summary text,
    explanation text,
    fix_snippet text,
    confidence text default 'high',
    meta jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists findings_scan_idx on public.findings (scan_id);

alter table public.findings enable row level security;

create policy "findings_owner_all"
    on public.findings for all
    using (
        exists (
            select 1 from public.scans s
            where s.id = findings.scan_id
              and s.user_id = auth.uid()
        )
    )
    with check (
        exists (
            select 1 from public.scans s
            where s.id = findings.scan_id
              and s.user_id = auth.uid()
        )
    );
