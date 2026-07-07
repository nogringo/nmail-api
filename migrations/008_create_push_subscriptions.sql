-- Push destinations registered by app clients. A subscription is owned by the
-- NIP-98 signing pubkey and is unique per transport destination for that pubkey.
create table if not exists push_subscriptions (
  pubkey char(64) not null references accounts (pubkey) on update cascade on delete cascade,
  transport text not null,
  destination text not null,
  p256dh text,
  auth text,
  instance text,
  constraint push_subscriptions_pubkey_hex check (pubkey ~ '^[0-9a-f]{64}$'),
  constraint push_subscriptions_transport check (transport in ('fcm', 'unifiedpush')),
  constraint push_subscriptions_destination_not_empty check (length(destination) > 0),
  constraint push_subscriptions_primary_key primary key (pubkey, transport, destination)
);

create index if not exists push_subscriptions_pubkey_idx
  on push_subscriptions (pubkey);
