CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'notice' CHECK(kind IN ('notice','gift')),
  gift_code TEXT,
  image_url TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_announcements_active_created ON announcements(active, created_at DESC);
