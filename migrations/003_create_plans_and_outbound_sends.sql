create table if not exists plans (
  name text primary key,
  per_minute integer not null,
  per_hour integer not null,
  per_day integer not null,
  max_message_bytes bigint not null,
  max_recipients integer not null,
  is_default boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint plans_name_slug check (name ~ '^[a-z0-9_-]+$'),
  constraint plans_per_minute_positive check (per_minute >= 0),
  constraint plans_per_hour_positive check (per_hour >= 0),
  constraint plans_per_day_positive check (per_day >= 0),
  constraint plans_max_message_bytes_positive check (max_message_bytes >= 0),
  constraint plans_max_recipients_positive check (max_recipients >= 0)
);

-- At most one plan can be the fallback applied to pubkeys without an assignment.
create unique index if not exists plans_single_default_idx
  on plans (is_default)
  where is_default;

insert into plans (name, per_minute, per_hour, per_day, max_message_bytes, max_recipients, is_default)
values
  ('free', 5, 30, 50, 10485760, 5, true),
  ('premium', 10, 100, 500, 26214400, 10, false)
on conflict (name) do nothing;

create table if not exists pubkey_plans (
  pubkey char(64) not null primary key,
  plan text not null references plans (name) on update cascade on delete restrict,
  updated_at timestamptz not null default now(),
  constraint pubkey_plans_pubkey_hex check (pubkey ~ '^[0-9a-f]{64}$')
);

create index if not exists pubkey_plans_plan_idx on pubkey_plans (plan);

create table if not exists outbound_sends (
  id bigserial primary key,
  pubkey char(64) not null,
  gift_wrap_id text,
  created_at timestamptz not null default now(),
  constraint outbound_sends_pubkey_hex check (pubkey ~ '^[0-9a-f]{64}$')
);

create index if not exists outbound_sends_pubkey_created_idx
  on outbound_sends (pubkey, created_at desc);

-- Dedupe retries of the same gift wrap so a re-asked message is not double counted.
create unique index if not exists outbound_sends_gift_wrap_idx
  on outbound_sends (gift_wrap_id)
  where gift_wrap_id is not null;
