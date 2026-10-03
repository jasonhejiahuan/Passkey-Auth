-- Preserve existing identities and credentials; all existing credentials stay enabled.
ALTER TABLE credentials ADD COLUMN disabled_at INTEGER;
CREATE INDEX credentials_user_status ON credentials(user_id, disabled_at);
