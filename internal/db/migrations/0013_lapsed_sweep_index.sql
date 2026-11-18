-- Lets the lapsed-account sweep (ListLapsedManagedAccountIDs) read one page
-- of candidates through an index instead of a full accounts scan plus a sort
-- per page. The key is the exact expression pair the listing filters and
-- orders by, (julianday(lapsed_at), id), so a page is a range seek that stops
-- at LIMIT. Partial on lapsed_at IS NOT NULL: only lapsed managed accounts
-- are indexed, so a self-hosted install carries an empty index.
CREATE INDEX IF NOT EXISTS idx_accounts_lapsed_julianday ON accounts (julianday(lapsed_at), id) WHERE lapsed_at IS NOT NULL;
