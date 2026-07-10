alter table push_subscriptions
  add column if not exists language text not null default 'en';

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'push_subscriptions_language_not_empty'
  ) then
    alter table push_subscriptions
      add constraint push_subscriptions_language_not_empty check (length(language) > 0);
  end if;
end $$;
