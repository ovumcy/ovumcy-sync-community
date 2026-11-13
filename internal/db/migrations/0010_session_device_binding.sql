-- Binds a session to the device it attached. NULL means unbound: sessions
-- that existed before this migration, and any session that has not called
-- POST /sync/devices yet. The first attach binds the caller's session and the
-- binding never moves; removing that device revokes every session bound to it.
ALTER TABLE sessions ADD COLUMN device_id TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_account_device ON sessions(account_id, device_id);
