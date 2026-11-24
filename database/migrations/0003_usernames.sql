ALTER TABLE users ADD COLUMN username TEXT;
UPDATE users SET username = lower(replace(substr(email, 1, instr(email, '@') - 1), '.', '_')) || '_' || substr(id, 1, 6) WHERE username IS NULL;
CREATE UNIQUE INDEX idx_users_username ON users(username);