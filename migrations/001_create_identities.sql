create table if not exists identities (
  id bigserial primary key,
  domain text not null,
  local_part text not null,
  pubkey char(64) not null,
  relays jsonb not null default '[]'::jsonb,
  visibility text not null default 'public',
  mail_enabled boolean not null default true,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint identities_domain_lowercase check (domain = lower(domain)),
  constraint identities_local_part_lowercase check (local_part = lower(local_part)),
  constraint identities_pubkey_hex check (pubkey ~ '^[0-9a-f]{64}$'),
  constraint identities_relays_array check (jsonb_typeof(relays) = 'array'),
  constraint identities_visibility check (visibility in ('public', 'private')),
  constraint identities_unique_name unique (domain, local_part)
);

create index if not exists identities_public_lookup_idx
  on identities (domain, local_part)
  where active and visibility = 'public';

create index if not exists identities_mail_lookup_idx
  on identities (domain, local_part)
  where active and mail_enabled;
