-- =====================================================================
-- AT Fitness v84 · Community profiles (display name) + 24-hour Stories
-- Additive migration. Run AFTER supabase_setup.sql.
-- Paste the whole file into Supabase → SQL Editor → Run.
-- Safe to run again (idempotent). Does not touch existing posts or data.
-- If you ever re-run supabase_setup.sql, run this file again afterwards
-- (setup resets the profile column permissions).
-- =====================================================================

-- 1. Profiles: optional display name (shown above the @username)
alter table public.profiles add column if not exists display_name text;
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_display_name_len') then
    alter table public.profiles add constraint profiles_display_name_len
      check (display_name is null or length(display_name) <= 40);
  end if;
end $$;
grant update (username, display_name, avatar_url, bio) on public.profiles to authenticated;

-- 2. Stories: photo + optional text, visible for 24 hours
create table if not exists public.stories (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  image_path  text not null check (length(image_path) <= 300),
  caption     text check (caption is null or length(caption) <= 200),
  visibility  text not null default 'public' check (visibility in ('public','followers')),
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default (now() + interval '24 hours'),
  constraint stories_max_24h check (expires_at <= created_at + interval '24 hours 1 minute')
);
create index if not exists stories_user_idx    on public.stories (user_id, expires_at desc);
create index if not exists stories_expires_idx on public.stories (expires_at);

alter table public.stories enable row level security;
revoke all on public.stories from anon;
grant select, insert, delete on public.stories to authenticated;

drop policy if exists stories_read   on public.stories;
drop policy if exists stories_insert on public.stories;
drop policy if exists stories_delete on public.stories;
-- expired stories are invisible to everyone; blocked users and banned authors are excluded;
-- 'followers' stories only for people who follow the author
create policy stories_read on public.stories for select to authenticated using (
  expires_at > now() and (
    user_id = auth.uid() or public.is_staff() or (
      not public.is_banned(user_id)
      and not public.is_blocked_between(auth.uid(), user_id)
      and (visibility = 'public' or public.follows_user(user_id))
    )));
create policy stories_insert on public.stories for insert to authenticated
  with check (user_id = auth.uid() and not public.is_banned()
              and expires_at <= now() + interval '24 hours 1 minute');
create policy stories_delete on public.stories for delete to authenticated
  using (user_id = auth.uid() or public.is_staff());

-- 3. Storage bucket for story photos (private; signed URLs only)
--    Files go in <user id>/<file name>, max 5 MB, images only.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('story-images', 'story-images', false, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists story_images_read   on storage.objects;
drop policy if exists story_images_insert on storage.objects;
drop policy if exists story_images_delete on storage.objects;
-- a story photo can be read only while its story row is visible to you (same rules as above)
create policy story_images_read on storage.objects for select to authenticated using (
  bucket_id = 'story-images' and (
    (storage.foldername(name))[1] = auth.uid()::text
    or exists (select 1 from public.stories s where s.image_path = storage.objects.name)));
create policy story_images_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'story-images' and (storage.foldername(name))[1] = auth.uid()::text
              and not public.is_banned());
create policy story_images_delete on storage.objects for delete to authenticated
  using (bucket_id = 'story-images' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_staff()));

-- 4. Optional housekeeping: remove story rows that expired more than a day ago.
--    (Expired stories are already hidden by the policy above.) Run manually or schedule with pg_cron:
--    select public.purge_expired_stories();
create or replace function public.purge_expired_stories() returns integer
language sql security definer set search_path = '' as $$
  with d as (delete from public.stories where expires_at < now() - interval '1 day' returning 1)
  select count(*)::int from d;
$$;
revoke all on function public.purge_expired_stories() from public, anon, authenticated;
