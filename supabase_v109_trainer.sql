-- AT Fitness v109 — Personal Trainer accounts.
-- Run in Supabase → SQL Editor AFTER supabase_setup.sql and the v84–v89 files. Safe to run more than once.
-- Privacy: a trainer can only read what a client has explicitly shared, only while the coaching link is active.
-- Her areas (her_cycle, her_preg, her_cond) are separate opt-ins and are never shared by default.

create table if not exists public.trainer_profiles (
  user_id    uuid primary key references public.profiles(id) on delete cascade,
  active     boolean not null default true,
  bio        text check (bio is null or length(bio) <= 300),
  created_at timestamptz not null default now()
);

create table if not exists public.trainer_invites (
  code       text primary key check (code ~ '^[A-Z0-9]{8}$'),
  trainer_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '14 days',
  used_by    uuid references public.profiles(id) on delete set null,
  used_at    timestamptz
);
create index if not exists trainer_invites_trainer_idx on public.trainer_invites (trainer_id);

create table if not exists public.trainer_links (
  id         uuid primary key default gen_random_uuid(),
  trainer_id uuid not null references public.profiles(id) on delete cascade,
  client_id  uuid not null references public.profiles(id) on delete cascade,
  status     text not null default 'active' check (status in ('active','revoked')),
  share      jsonb not null default '{}'::jsonb,
  consent_at timestamptz not null default now(),
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  constraint trainer_links_not_self check (trainer_id <> client_id)
);
create unique index if not exists trainer_links_active_pair on public.trainer_links (trainer_id, client_id) where status = 'active';
create index if not exists trainer_links_client_idx on public.trainer_links (client_id);

create table if not exists public.client_shares (
  client_id  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  area       text not null check (area in ('train','diet','weight','month','her_cycle','her_preg','her_cond')),
  data       jsonb not null default '{}'::jsonb check (pg_column_size(data) <= 262144),
  updated_at timestamptz not null default now(),
  primary key (client_id, area)
);

create table if not exists public.trainer_assignments (
  id          uuid primary key default gen_random_uuid(),
  trainer_id  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  client_id   uuid not null references public.profiles(id) on delete cascade,
  kind        text not null check (kind in ('train','diet')),
  name        text not null check (length(name) between 1 and 120),
  payload     jsonb not null check (pg_column_size(payload) <= 262144),
  status      text not null default 'sent' check (status in ('sent','accepted','declined')),
  created_at  timestamptz not null default now(),
  answered_at timestamptz
);
create index if not exists trainer_assign_client_idx on public.trainer_assignments (client_id);

-- helpers (security definer so policies don't recurse)
create or replace function public.is_trainer(u uuid default auth.uid()) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.trainer_profiles where user_id = u and active) $$;
create or replace function public.coach_can_read(client uuid, a text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.trainer_links l
    where l.client_id = client and l.trainer_id = auth.uid() and l.status = 'active'
      and coalesce((l.share ->> a)::boolean, false)) $$;
create or replace function public.coach_active(client uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.trainer_links l where l.client_id = client and l.trainer_id = auth.uid() and l.status = 'active') $$;

alter table public.trainer_profiles    enable row level security;
alter table public.trainer_invites     enable row level security;
alter table public.trainer_links       enable row level security;
alter table public.client_shares       enable row level security;
alter table public.trainer_assignments enable row level security;

drop policy if exists tp_read on public.trainer_profiles;
create policy tp_read on public.trainer_profiles for select to authenticated using (true);
drop policy if exists tp_ins on public.trainer_profiles;
create policy tp_ins on public.trainer_profiles for insert to authenticated with check (user_id = auth.uid());
drop policy if exists tp_upd on public.trainer_profiles;
create policy tp_upd on public.trainer_profiles for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists ti_read on public.trainer_invites;
create policy ti_read on public.trainer_invites for select to authenticated using (trainer_id = auth.uid());
drop policy if exists ti_ins on public.trainer_invites;
create policy ti_ins on public.trainer_invites for insert to authenticated with check (trainer_id = auth.uid() and public.is_trainer() and used_by is null);
drop policy if exists ti_del on public.trainer_invites;
create policy ti_del on public.trainer_invites for delete to authenticated using (trainer_id = auth.uid());

-- links: both sides read; changes only through the functions below
drop policy if exists tl_read on public.trainer_links;
create policy tl_read on public.trainer_links for select to authenticated using (trainer_id = auth.uid() or client_id = auth.uid());

drop policy if exists cs_own on public.client_shares;
create policy cs_own on public.client_shares for all to authenticated using (client_id = auth.uid()) with check (client_id = auth.uid());
drop policy if exists cs_coach on public.client_shares;
create policy cs_coach on public.client_shares for select to authenticated using (public.coach_can_read(client_id, area));

drop policy if exists ta_read on public.trainer_assignments;
create policy ta_read on public.trainer_assignments for select to authenticated using (trainer_id = auth.uid() or client_id = auth.uid());
drop policy if exists ta_ins on public.trainer_assignments;
create policy ta_ins on public.trainer_assignments for insert to authenticated with check (trainer_id = auth.uid() and status = 'sent' and public.coach_active(client_id));
drop policy if exists ta_del on public.trainer_assignments;
create policy ta_del on public.trainer_assignments for delete to authenticated using (trainer_id = auth.uid() and status = 'sent');

-- RPCs
create or replace function public.trainer_invite_info(p_code text) returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('trainer_id', i.trainer_id, 'username', p.username, 'display_name', p.display_name,
         'valid', i.used_by is null and i.expires_at > now() and public.is_trainer(i.trainer_id))
  from public.trainer_invites i join public.profiles p on p.id = i.trainer_id where i.code = upper(p_code) $$;

create or replace function public.clean_share(s jsonb) returns jsonb
language sql immutable set search_path = '' as $$
  select coalesce(jsonb_object_agg(k, true), '{}'::jsonb) from jsonb_each(coalesce(s,'{}'::jsonb)) e(k, v)
  where k in ('train','diet','weight','month','her_cycle','her_preg','her_cond') and v = 'true'::jsonb $$;

create or replace function public.trainer_accept_invite(p_code text, p_share jsonb) returns uuid
language plpgsql security definer set search_path = '' as $$
declare i public.trainer_invites; lid uuid;
begin
  if auth.uid() is null then raise exception 'sign in first'; end if;
  select * into i from public.trainer_invites where code = upper(p_code) for update;
  if not found or i.used_by is not null or i.expires_at <= now() or not public.is_trainer(i.trainer_id) then raise exception 'invite not valid'; end if;
  if i.trainer_id = auth.uid() then raise exception 'you cannot coach yourself'; end if;
  update public.trainer_links set status='revoked', revoked_at=now() where trainer_id=i.trainer_id and client_id=auth.uid() and status='active';
  insert into public.trainer_links (trainer_id, client_id, share) values (i.trainer_id, auth.uid(), public.clean_share(p_share)) returning id into lid;
  update public.trainer_invites set used_by = auth.uid(), used_at = now() where code = i.code;
  return lid;
end $$;

create or replace function public.trainer_set_share(p_link uuid, p_share jsonb) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.trainer_links set share = public.clean_share(p_share), consent_at = now()
   where id = p_link and client_id = auth.uid() and status = 'active';
  if not found then raise exception 'not your active link'; end if;
end $$;

create or replace function public.trainer_end_link(p_link uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.trainer_links set status = 'revoked', revoked_at = now(), share = '{}'::jsonb
   where id = p_link and (client_id = auth.uid() or trainer_id = auth.uid()) and status = 'active';
  if not found then raise exception 'link not found'; end if;
end $$;

create or replace function public.trainer_answer(p_id uuid, p_accept boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.trainer_assignments set status = case when p_accept then 'accepted' else 'declined' end, answered_at = now()
   where id = p_id and client_id = auth.uid() and status = 'sent';
  if not found then raise exception 'assignment not found'; end if;
end $$;

revoke all on function public.trainer_accept_invite(text, jsonb), public.trainer_set_share(uuid, jsonb), public.trainer_end_link(uuid), public.trainer_answer(uuid, boolean), public.trainer_invite_info(text) from public, anon;
grant execute on function public.trainer_accept_invite(text, jsonb), public.trainer_set_share(uuid, jsonb), public.trainer_end_link(uuid), public.trainer_answer(uuid, boolean), public.trainer_invite_info(text), public.is_trainer(uuid), public.coach_can_read(uuid, text), public.coach_active(uuid), public.clean_share(jsonb) to authenticated;
grant select, insert, update, delete on public.trainer_profiles, public.trainer_invites, public.trainer_links, public.client_shares, public.trainer_assignments to authenticated;

notify pgrst, 'reload schema';
