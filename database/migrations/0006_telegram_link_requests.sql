CREATE TABLE IF NOT EXISTS telegram_link_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  telegram_user_id TEXT NOT NULL,
  chat_id TEXT NOT NULL,
  username TEXT,
  first_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','confirmed','expired','cancelled')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_telegram_link_requests_user_status ON telegram_link_requests(user_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_telegram_link_requests_telegram_status ON telegram_link_requests(telegram_user_id,status,created_at);
