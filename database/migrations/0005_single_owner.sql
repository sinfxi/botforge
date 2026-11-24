-- Only one owner may be created, including concurrent first-time setup requests.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_single_owner
ON users(role)
WHERE role = 'owner';
