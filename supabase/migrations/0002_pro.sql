-- VMAXweb Pro features (Supabase / PostgreSQL)
-- Account settings, API keys and scheduled scans. Run after 0001_init.sql.

-- ---------------------------------------------------------------------------
-- account_settings: one row per user holding Pro configuration
-- ---------------------------------------------------------------------------
create table if not exists public.account_settings (
    user_id uuid primary key references public.profiles (id) on delete cascade,
    brand_name text,
    logo_base64 text,
    brand_color text,
    slack_webhook_url text,
    webhook_url text,
    webhook_secret text,
    alert_email text,
    alert_min_severity text not null default 'critical'
        check (alert_min_severity in ('critical', 'warning', 'info')),
    priority_support boolean not null default false,
    updated_at timestamptz not null default now()
);

alter table public.account_settings enable row level security;

create policy "account_settings_owner_all"
    on public.account_settings for all
    using (auth.uid() = user_id)
    with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- api_keys: hashed Pro API credentials (service-role only)
-- ---------------------------------------------------------------------------
create table if not exists public.api_keys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references public.profiles (id) on delete cascade,
    name text not null default 'API key',
    prefix text not null,
    key_hash text not null unique,
    created_at timestamptz not null default now(),
    last_used_at timestamptz
);

create index if not exists api_keys_user_idx on public.api_keys (user_id);

alter table public.api_keys enable row level security;

create policy "api_keys_owner_all"
    on public.api_keys for all
    using (auth.uid() = user_id)
    with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- scheduled_scans: recurring audits per target
-- ---------------------------------------------------------------------------
create table if not exists public.scheduled_scans (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references public.profiles (id) on delete cascade,
    url text not null,
    cadence text not null default 'daily' check (cadence in ('daily', 'weekly')),
    verification_token text,
    enabled boolean not null default true,
    next_run_at timestamptz not null default now(),
    last_run_at timestamptz,
    last_scan_id uuid references public.scans (id) on delete set null,
    created_at timestamptz not null default now()
);

create index if not exists scheduled_scans_due_idx
    on public.scheduled_scans (enabled, next_run_at);

alter table public.scheduled_scans enable row level security;

create policy "scheduled_scans_owner_all"
    on public.scheduled_scans for all
    using (auth.uid() = user_id)
    with check (auth.uid() = user_id);
