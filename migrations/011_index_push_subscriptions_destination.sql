-- Unauthenticated disables delete by destination alone, which the primary key
-- cannot serve: it leads with pubkey.
create index if not exists push_subscriptions_destination_idx
  on push_subscriptions (transport, destination);
