-- AT Fitness v89 — voice message fix (optional, safe to re-run).
-- Widens the private voice-messages bucket to accept every audio format phones record in
-- (iPhone Safari reports audio/mp4, sometimes video/mp4 or audio/x-m4a; Android/Chrome audio/webm).
-- The app already normalises uploads to audio/mp4 or audio/webm, so this is belt-and-braces.
-- Bucket stays private, 10 MB max; access is still limited to the two chat participants by the v87 policies.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('voice-messages', 'voice-messages', false, 10485760,
        array['audio/*','audio/mp4','audio/x-m4a','audio/m4a','audio/aac','audio/mpeg','audio/webm','audio/ogg','audio/wav','video/mp4','video/webm'])
on conflict (id) do update
  set public = false,
      file_size_limit = 10485760,
      allowed_mime_types = excluded.allowed_mime_types;
