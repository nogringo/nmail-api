-- Idempotency keys for inbound push notifications. Multiple Nostr listeners may
-- observe the same event and call /inbound/notifications concurrently, but only
-- the first request for a recipient/event pair should dispatch push messages.
create table if not exists inbound_notification_deliveries (
  recipient_pubkey char(64) not null,
  event_id char(64) not null,
  created_at timestamptz not null default now(),
  constraint inbound_notification_deliveries_recipient_pubkey_hex check (recipient_pubkey ~ '^[0-9a-f]{64}$'),
  constraint inbound_notification_deliveries_event_id_hex check (event_id ~ '^[0-9a-f]{64}$'),
  constraint inbound_notification_deliveries_primary_key primary key (recipient_pubkey, event_id)
);

create index if not exists inbound_notification_deliveries_created_at_idx
  on inbound_notification_deliveries (created_at);
