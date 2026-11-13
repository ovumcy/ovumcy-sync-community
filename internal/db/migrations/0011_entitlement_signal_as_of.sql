-- Orders the managed bridge's entitlement signals (POST /managed/accounts/
-- {account_id}/premium). Holds the as-of instant, in Unix nanoseconds, of
-- the newest lapse or reactivation signal applied to a managed account, so a
-- delayed or retried signal older than one already applied is refused and a
-- stale reactivation can never undo a newer lapse. NULL until the first
-- signal; never set for a self-hosted account.
ALTER TABLE accounts ADD COLUMN entitlement_signal_as_of INTEGER;
