-- AT Fitness v85 — full account cloud backup / sync (one row per app storage key).
-- Run in Supabase → SQL Editor AFTER supabase_setup.sql. Safe to run more than once (idempotent, additive).
-- Privacy: Row Level Security — every user can only read/write/delete their OWN rows. Anonymous users have no access.

create table if not exists public.user_data (
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  key         text not null,
  value       jsonb,
  is_raw      boolean not null default false,
  size        integer not null default 0,
  device      text,
  app_version text,
  updated_at  timestamptz not null default now(),   -- when the value was changed on the device (newest wins)
  synced_at   timestamptz not null default now(),   -- server write time (used for incremental pulls)
  primary key (user_id, key)
);

do $$ begin
  if not exists (select 1 from pg_constraint where conname='user_data_key_chk') then
    alter table public.user_data add constraint user_data_key_chk
      check (length(key) between 1 and 200 and (key like 'tt\_%' or key = 'trainingTracker.v1'));
  end if;
  if not exists (select 1 from pg_constraint where conname='user_data_size_chk') then
    alter table public.user_data add constraint user_data_size_chk check (octet_length(coalesce(value::text,'')) <= 5000000);
  end if;
  if not exists (select 1 from pg_constraint where conname='user_data_meta_chk') then
    alter table public.user_data add constraint user_data_meta_chk
      check ((device is null or length(device) <= 120) and (app_version is null or length(app_version) <= 20));
  end if;
end $$;

create index if not exists user_data_sync_idx on public.user_data (user_id, synced_at);

alter table public.user_data enable row level security;
revoke all on public.user_data from anon, public;
grant select, insert, update, delete on public.user_data to authenticated;

drop policy if exists user_data_select on public.user_data;
drop policy if exists user_data_insert on public.user_data;
drop policy if exists user_data_update on public.user_data;
drop policy if exists user_data_delete on public.user_data;
create policy user_data_select on public.user_data for select to authenticated using (user_id = auth.uid());
create policy user_data_insert on public.user_data for insert to authenticated with check (user_id = auth.uid());
create policy user_data_update on public.user_data for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy user_data_delete on public.user_data for delete to authenticated using (user_id = auth.uid());

-- size bookkeeping, server timestamps, no future-dating, 50 MB per-user quota
create or replace function public.user_data_guard() returns trigger language plpgsql set search_path = public as $$
declare tot bigint;
begin
  if tg_op = 'UPDATE' then new.user_id := old.user_id; new.key := old.key; end if;
  new.size := octet_length(coalesce(new.value::text, ''));
  new.synced_at := clock_timestamp();
  if new.updated_at > now() + interval '5 minutes' then new.updated_at := now(); end if;
  select coalesce(sum(size), 0) into tot from public.user_data where user_id = new.user_id and key <> new.key;
  if tot + new.size > 50000000 then
    raise exception 'Backup quota exceeded (50 MB per account)' using errcode = '54000';
  end if;
  return new;
end $$;
drop trigger if exists user_data_guard on public.user_data;
create trigger user_data_guard before insert or update on public.user_data
  for each row execute function public.user_data_guard();

-- batch upsert: newest updated_at per key wins; returns the server rows that were NEWER (rejected items)
create or replace function public.user_data_put(p_items jsonb) returns setof public.user_data
language plpgsql security invoker set search_path = public as $$
declare it jsonb; r public.user_data;
begin
  if auth.uid() is null then raise exception 'not signed in' using errcode = '42501'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) > 500 then
    raise exception 'p_items must be an array of at most 500 items' using errcode = '22023';
  end if;
  for it in select * from jsonb_array_elements(p_items) loop
    insert into public.user_data as u (user_id, key, value, is_raw, updated_at, device, app_version)
    values (auth.uid(), it->>'key', it->'value', coalesce((it->>'is_raw')::boolean, false),
            coalesce((it->>'updated_at')::timestamptz, now()), left(it->>'device', 120), left(it->>'app_version', 20))
    on conflict (user_id, key) do update
      set value = excluded.value, is_raw = excluded.is_raw, updated_at = excluded.updated_at,
          device = excluded.device, app_version = excluded.app_version
      where u.updated_at < excluded.updated_at;
    if not found then
      select * into r from public.user_data where user_id = auth.uid() and key = it->>'key';
      if found then return next r; end if;
    end if;
  end loop;
  return;
end $$;
revoke all on function public.user_data_put(jsonb) from public, anon;
grant execute on function public.user_data_put(jsonb) to authenticated;

notify pgrst, 'reload schema';
