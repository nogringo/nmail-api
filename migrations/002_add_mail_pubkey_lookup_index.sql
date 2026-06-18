create index if not exists identities_mail_pubkey_lookup_idx
  on identities (domain, pubkey)
  where active and mail_enabled;
