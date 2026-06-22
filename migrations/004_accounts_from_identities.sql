-- Move person-level state (active, mail_enabled, relays) off identities and onto
-- accounts, keyed by pubkey. Run after 003 created the accounts table.

-- 1. Create one account per existing pubkey, OR-ing the per-alias flags.
insert into accounts (pubkey, active, mail_enabled)
select pubkey, bool_or(active), bool_or(mail_enabled)
from identities
group by pubkey
on conflict (pubkey) do nothing;

-- 2. Carry over relays from the most recently updated alias of each pubkey.
update accounts a
set relays = i.relays
from (
  select distinct on (pubkey) pubkey, relays
  from identities
  order by pubkey, updated_at desc
) i
where i.pubkey = a.pubkey;

-- 3. The old partial indexes depend on columns we are about to drop.
drop index if exists identities_public_lookup_idx;
drop index if exists identities_mail_lookup_idx;
drop index if exists identities_mail_pubkey_lookup_idx;

-- 4. Drop the moved columns and tie identities to accounts.
alter table identities
  drop column if exists relays,
  drop column if exists mail_enabled,
  drop column if exists active;

alter table identities
  add constraint identities_pubkey_fk
  foreign key (pubkey) references accounts (pubkey) on update cascade on delete cascade;

create index if not exists identities_pubkey_idx on identities (pubkey);

create index if not exists identities_public_lookup_idx
  on identities (domain, local_part)
  where visibility = 'public';
