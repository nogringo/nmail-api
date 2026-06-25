-- Role mailbox mail (abuse@, postmaster@, ...) received from the haraka-webhook
-- role webhook. These mailboxes are reserved (not user-claimable), so their mail
-- belongs to the operator and is read from /admin. content_hash = sha256(body-mime)
-- makes plugin retries idempotent (the body is identical across attempts).
create table if not exists role_messages (
  id bigserial primary key,
  recipient text not null,
  sender text not null default '',
  from_addr text not null default '',
  subject text not null default '',
  headers jsonb not null default '[]'::jsonb,
  body_mime text not null default '',
  content_hash char(64) not null,
  received_at timestamptz not null default now(),
  constraint role_messages_content_hash_lowercase check (content_hash = lower(content_hash)),
  constraint role_messages_content_hash_unique unique (content_hash)
);

create index if not exists role_messages_received_idx on role_messages (received_at desc);
