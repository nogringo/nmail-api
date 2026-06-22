create table if not exists domains (
  domain text primary key,
  created_at timestamptz not null default now(),
  constraint domains_lowercase check (domain = lower(domain))
);
