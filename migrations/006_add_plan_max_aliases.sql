-- max_aliases: how many provisioned aliases (database-only addresses) an account
-- on this plan may claim. Pubkey-encoded addresses do not count and are not
-- claimable, so they are unaffected.
alter table plans add column if not exists max_aliases integer not null default 2;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'plans_max_aliases_positive'
  ) then
    alter table plans add constraint plans_max_aliases_positive check (max_aliases >= 0);
  end if;
end $$;

update plans set max_aliases = 10 where name = 'premium';

-- Count a pubkey's claimed aliases efficiently (no plain pubkey index existed).
create index if not exists identities_pubkey_idx on identities (pubkey);
