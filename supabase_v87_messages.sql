-- AT Fitness v87 — private 1:1 messages (text + voice with transcript).
-- Run in Supabase → SQL Editor AFTER supabase_setup.sql, v84, v85 and v86 files. Safe to run more than once.
-- Privacy: only the two people in a conversation can read its messages or voice files. Blocks are respected.

-- 1. Tables
create table if not exists public.conversations (
  id              uuid primary key default gen_random_uuid(),
  user_a          uuid not null references public.profiles(id) on delete cascade,
  user_b          uuid not null references public.profiles(id) on delete cascade,
  created_at      timestamptz not null default now(),
  last_message_at timestamptz not null default now(),
  constraint conversations_pair_order check (user_a < user_b),
  constraint conversations_pair_unique unique (user_a, user_b)
);
create table if not exists public.conversation_participants (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id         uuid not null references public.profiles(id) on delete cascade,
  joined_at       timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index if not exists conv_participants_user_idx on public.conversation_participants (user_id);

create table if not exists public.messages (
  id              uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id       uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  kind            text not null default 'text',
  body            text,
  voice_path      text,
  duration_ms     integer,
  size_bytes      integer,
  transcript      text,
  created_at      timestamptz not null default now(),
  read_at         timestamptz
);
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'messages_shape_chk') then
    alter table public.messages add constraint messages_shape_chk check (
      (kind = 'text'  and body is not null and length(btrim(body)) between 1 and 4000 and voice_path is null)
   or (kind = 'voice' and voice_path is not null and length(voice_path) <= 300
       and duration_ms between 300 and 185000 and (size_bytes is null or size_bytes <= 10485760)
       and (body is null or length(body) <= 500)));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'messages_transcript_len') then
    alter table public.messages add constraint messages_transcript_len check (transcript is null or length(transcript) <= 5000);
  end if;
end $$;
create index if not exists messages_conv_idx on public.messages (conversation_id, created_at desc);
create index if not exists messages_unread_idx on public.messages (conversation_id) where read_at is null;

-- 2. Helpers
create or replace function public.is_participant(c uuid, u uuid default auth.uid()) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.conversation_participants p where p.conversation_id = c and p.user_id = u);
$$;
create or replace function public.conversation_other(c uuid, u uuid default auth.uid()) returns uuid
language sql stable security definer set search_path = '' as $$
  select case when x.user_a = u then x.user_b else x.user_a end from public.conversations x where x.id = c;
$$;
create or replace function public.safe_uuid(t text) returns uuid language sql immutable as $$
  select case when t ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then t::uuid else null end;
$$;

-- start (or reopen) a 1:1 conversation; refuses self, blocked pairs, banned users
create or replace function public.start_conversation(other uuid) returns uuid
language plpgsql security definer set search_path = '' as $$
declare me uuid := auth.uid(); a uuid; b uuid; cid uuid;
begin
  if me is null then raise exception 'not signed in' using errcode = '42501'; end if;
  if other is null or other = me then raise exception 'cannot message yourself' using errcode = '22023'; end if;
  if not exists (select 1 from public.profiles where id = other) then raise exception 'user not found' using errcode = '22023'; end if;
  if public.is_blocked_between(me, other) then raise exception 'You can’t message this user' using errcode = '42501'; end if;
  if public.is_banned(me) then raise exception 'Your account is suspended' using errcode = '42501'; end if;
  a := least(me, other); b := greatest(me, other);
  insert into public.conversations (user_a, user_b) values (a, b) on conflict (user_a, user_b) do nothing;
  select id into cid from public.conversations where user_a = a and user_b = b;
  insert into public.conversation_participants (conversation_id, user_id) values (cid, a), (cid, b) on conflict do nothing;
  return cid;
end $$;
revoke all on function public.start_conversation(uuid) from public, anon;
grant execute on function public.start_conversation(uuid) to authenticated;

-- 3. RLS
alter table public.conversations enable row level security;
alter table public.conversation_participants enable row level security;
alter table public.messages enable row level security;
revoke all on public.conversations, public.conversation_participants, public.messages from anon, public, authenticated;
grant select on public.conversations, public.conversation_participants to authenticated;
grant select, insert, delete on public.messages to authenticated;
grant update (read_at) on public.messages to authenticated;

drop policy if exists conversations_select on public.conversations;
create policy conversations_select on public.conversations for select to authenticated using (public.is_participant(id));
drop policy if exists conv_participants_select on public.conversation_participants;
create policy conv_participants_select on public.conversation_participants for select to authenticated using (public.is_participant(conversation_id));

drop policy if exists messages_select on public.messages;
drop policy if exists messages_insert on public.messages;
drop policy if exists messages_update on public.messages;
drop policy if exists messages_delete on public.messages;
create policy messages_select on public.messages for select to authenticated using (public.is_participant(conversation_id));
create policy messages_insert on public.messages for insert to authenticated with check (
  sender_id = auth.uid() and public.is_participant(conversation_id)
  and not public.is_banned()
  and not public.is_blocked_between(auth.uid(), public.conversation_other(conversation_id))
  and (voice_path is null or (split_part(voice_path, '/', 1) = conversation_id::text
                              and split_part(voice_path, '/', 2) like auth.uid()::text || '-%')));
-- only the recipient may set read_at
create policy messages_update on public.messages for update to authenticated
  using (public.is_participant(conversation_id) and sender_id <> auth.uid())
  with check (public.is_participant(conversation_id) and sender_id <> auth.uid());
create policy messages_delete on public.messages for delete to authenticated using (sender_id = auth.uid());

-- 4. Guard trigger: rate limit (30 messages / minute, 300 / day), stamp server time, bump conversation
create or replace function public.messages_guard() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    new.created_at := now(); new.read_at := null;
    if (select count(*) from public.messages where sender_id = new.sender_id and created_at > now() - interval '1 minute') >= 30
       or (select count(*) from public.messages where sender_id = new.sender_id and created_at > now() - interval '1 day') >= 300 then
      raise exception 'You’re sending messages too fast — try again in a minute' using errcode = '54000';
    end if;
  else
    -- read receipts only: nothing but read_at may change
    new.conversation_id := old.conversation_id; new.sender_id := old.sender_id; new.kind := old.kind; new.body := old.body;
    new.voice_path := old.voice_path; new.duration_ms := old.duration_ms; new.size_bytes := old.size_bytes;
    new.transcript := old.transcript; new.created_at := old.created_at;
  end if;
  return new;
end $$;
drop trigger if exists messages_guard on public.messages;
create trigger messages_guard before insert or update on public.messages for each row execute function public.messages_guard();

create or replace function public.messages_after() returns trigger language plpgsql security definer set search_path = '' as $$
declare other uuid;
begin
  update public.conversations set last_message_at = new.created_at where id = new.conversation_id;
  other := public.conversation_other(new.conversation_id, new.sender_id);
  if to_regclass('public.notifications') is not null and other is not null and other <> new.sender_id
     and not public.is_blocked_between(other, new.sender_id) then
    execute 'insert into public.notifications (recipient_id, actor_id, type, conversation_id) values ($1, $2, ''message'', $3) on conflict do nothing'
      using other, new.sender_id, new.conversation_id;
  end if;
  return null;
end $$;
drop trigger if exists messages_after on public.messages;
create trigger messages_after after insert on public.messages for each row execute function public.messages_after();
revoke all on function public.messages_guard(), public.messages_after() from public, anon, authenticated;

-- 5. Notifications (v86): add 'message' type + conversation link; one unread message notification per sender
do $$ begin
  if to_regclass('public.notifications') is not null then
    alter table public.notifications add column if not exists conversation_id uuid references public.conversations(id) on delete cascade;
    alter table public.notifications drop constraint if exists notifications_type_chk;
    alter table public.notifications add constraint notifications_type_chk
      check (type in ('like','comment','reply','mention','follow','message'));
    create unique index if not exists notifications_msg_once on public.notifications (recipient_id, actor_id) where type = 'message' and read_at is null;
  end if;
end $$;

-- 6. Private voice bucket: files at <conversation id>/<sender id>-<timestamp>.<ext>, max 10 MB, audio only
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('voice-messages', 'voice-messages', false, 10485760,
        array['audio/webm','audio/ogg','audio/mp4','audio/mpeg','audio/aac','audio/x-m4a','audio/wav'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists voice_read on storage.objects;
drop policy if exists voice_insert on storage.objects;
drop policy if exists voice_delete on storage.objects;
create policy voice_read on storage.objects for select to authenticated using (
  bucket_id = 'voice-messages' and public.is_participant(public.safe_uuid((storage.foldername(name))[1])));
create policy voice_insert on storage.objects for insert to authenticated with check (
  bucket_id = 'voice-messages'
  and public.is_participant(public.safe_uuid((storage.foldername(name))[1]))
  and split_part(name, '/', 2) like auth.uid()::text || '-%'
  and not public.is_banned()
  and not public.is_blocked_between(auth.uid(), public.conversation_other(public.safe_uuid((storage.foldername(name))[1]))));
create policy voice_delete on storage.objects for delete to authenticated using (
  bucket_id = 'voice-messages' and split_part(name, '/', 2) like auth.uid()::text || '-%');

-- 7. Optional realtime for instant delivery
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;

notify pgrst, 'reload schema';
