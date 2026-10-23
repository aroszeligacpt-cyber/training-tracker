-- AT Fitness v86 — Community notifications (likes, comments, replies, mentions, follows).
-- Run in Supabase → SQL Editor AFTER supabase_setup.sql (and v84/v85 files). Safe to run more than once.
-- Notifications are created only by database triggers; users can read / mark-read / delete only their own.

create table if not exists public.notifications (
  id           uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  actor_id     uuid not null references public.profiles(id) on delete cascade,
  type         text not null,
  post_id      uuid references public.posts(id) on delete cascade,
  comment_id   uuid references public.comments(id) on delete cascade,
  read_at      timestamptz,
  created_at   timestamptz not null default now()
);
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'notifications_type_chk') then
    alter table public.notifications add constraint notifications_type_chk
      check (type in ('like','comment','reply','mention','follow'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'notifications_not_self') then
    alter table public.notifications add constraint notifications_not_self check (recipient_id <> actor_id);
  end if;
end $$;
create index if not exists notifications_recipient_idx on public.notifications (recipient_id, created_at desc);
create unique index if not exists notifications_like_once   on public.notifications (recipient_id, actor_id, post_id) where type = 'like';
create unique index if not exists notifications_follow_once on public.notifications (recipient_id, actor_id) where type = 'follow';
create unique index if not exists notifications_cmt_once    on public.notifications (recipient_id, comment_id, type) where comment_id is not null;
create unique index if not exists notifications_post_mention_once on public.notifications (recipient_id, post_id) where type = 'mention' and comment_id is null;

alter table public.notifications enable row level security;
revoke all on public.notifications from anon, public, authenticated;
grant select, delete on public.notifications to authenticated;
grant update (read_at) on public.notifications to authenticated;
drop policy if exists notifications_select on public.notifications;
drop policy if exists notifications_update on public.notifications;
drop policy if exists notifications_delete on public.notifications;
create policy notifications_select on public.notifications for select to authenticated using (recipient_id = auth.uid());
create policy notifications_update on public.notifications for update to authenticated using (recipient_id = auth.uid()) with check (recipient_id = auth.uid());
create policy notifications_delete on public.notifications for delete to authenticated using (recipient_id = auth.uid());

-- internal helper: insert unless self / blocked / banned actor; duplicates silently ignored
create or replace function public.notify_add(p_to uuid, p_actor uuid, p_type text, p_post uuid, p_comment uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_to is null or p_actor is null or p_to = p_actor then return; end if;
  if public.is_blocked_between(p_to, p_actor) then return; end if;
  insert into public.notifications (recipient_id, actor_id, type, post_id, comment_id)
  values (p_to, p_actor, p_type, p_post, p_comment) on conflict do nothing;
end $$;
revoke all on function public.notify_add(uuid, uuid, text, uuid, uuid) from public, anon, authenticated;

-- @mentions (max 5 distinct usernames per text)
create or replace function public.notify_mentions(p_body text, p_actor uuid, p_post uuid, p_comment uuid, p_skip uuid[])
returns void language plpgsql security definer set search_path = '' as $$
declare r record;
begin
  if p_body is null or position('@' in p_body) = 0 then return; end if;
  for r in select distinct p.id from public.profiles p
           where lower(p.username) in (select lower(m[1]) from regexp_matches(p_body, '@([A-Za-z0-9_.]{3,24})', 'g') as m limit 5)
  loop
    if not (r.id = any(coalesce(p_skip, '{}'))) then perform public.notify_add(r.id, p_actor, 'mention', p_post, p_comment); end if;
  end loop;
end $$;
revoke all on function public.notify_mentions(text, uuid, uuid, uuid, uuid[]) from public, anon, authenticated;

create or replace function public.trg_notify_like() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform public.notify_add((select user_id from public.posts where id = new.post_id), new.user_id, 'like', new.post_id, null);
  return null;
end $$;
create or replace function public.trg_unnotify_like() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  delete from public.notifications where type = 'like' and actor_id = old.user_id and post_id = old.post_id and read_at is null;
  return null;
end $$;
create or replace function public.trg_notify_comment() returns trigger language plpgsql security definer set search_path = '' as $$
declare owner uuid; r record;
begin
  select user_id into owner from public.posts where id = new.post_id;
  perform public.notify_add(owner, new.user_id, 'comment', new.post_id, new.id);
  -- reply: earlier commenters on the same post (not the owner, not the actor), max 20
  for r in select distinct c.user_id from public.comments c
           where c.post_id = new.post_id and c.id <> new.id and c.user_id <> new.user_id and c.user_id <> owner limit 20 loop
    perform public.notify_add(r.user_id, new.user_id, 'reply', new.post_id, new.id);
  end loop;
  perform public.notify_mentions(new.body, new.user_id, new.post_id, new.id, array[owner]);
  return null;
end $$;
create or replace function public.trg_notify_post() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform public.notify_mentions(new.body, new.user_id, new.id, null, null);
  return null;
end $$;
create or replace function public.trg_notify_follow() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform public.notify_add(new.followee_id, new.follower_id, 'follow', null, null);
  return null;
end $$;
revoke all on function public.trg_notify_like(), public.trg_unnotify_like(), public.trg_notify_comment(), public.trg_notify_post(), public.trg_notify_follow() from public, anon, authenticated;

drop trigger if exists notify_like on public.likes;
create trigger notify_like after insert on public.likes for each row execute function public.trg_notify_like();
drop trigger if exists unnotify_like on public.likes;
create trigger unnotify_like after delete on public.likes for each row execute function public.trg_unnotify_like();
drop trigger if exists notify_comment on public.comments;
create trigger notify_comment after insert on public.comments for each row execute function public.trg_notify_comment();
drop trigger if exists notify_post on public.posts;
create trigger notify_post after insert on public.posts for each row execute function public.trg_notify_post();
drop trigger if exists notify_follow on public.follows;
create trigger notify_follow after insert on public.follows for each row execute function public.trg_notify_follow();

-- keep the table small: notifications older than 90 days are removed when new ones arrive (cheap, indexed)
create or replace function public.trg_notify_prune() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  delete from public.notifications where recipient_id = new.recipient_id and created_at < now() - interval '90 days';
  return null;
end $$;
revoke all on function public.trg_notify_prune() from public, anon, authenticated;
drop trigger if exists notify_prune on public.notifications;
create trigger notify_prune after insert on public.notifications for each row execute function public.trg_notify_prune();

-- optional realtime (instant bell updates) if the Supabase realtime publication exists
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'notifications') then
    alter publication supabase_realtime add table public.notifications;
  end if;
end $$;

notify pgrst, 'reload schema';
