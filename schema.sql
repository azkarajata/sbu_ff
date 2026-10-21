-- Skema database Cloudflare D1 untuk Dashboard Freight Forwarder
CREATE TABLE IF NOT EXISTS rfqs (
  id          TEXT PRIMARY KEY,
  rfq         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  company     TEXT NOT NULL,
  moda        TEXT NOT NULL,
  term        TEXT NOT NULL,
  pol         TEXT NOT NULL,
  pod         TEXT NOT NULL,
  description TEXT NOT NULL,
  outcome     TEXT,              -- NULL | 'deal' | 'lost'
  created     INTEGER NOT NULL,  -- epoch ms
  cost_at     INTEGER,           -- waktu job sheet diunggah
  file_name   TEXT
);

CREATE TABLE IF NOT EXISTS files (
  rfq_id TEXT PRIMARY KEY REFERENCES rfqs(id) ON DELETE CASCADE,
  mime   TEXT NOT NULL,
  data   TEXT NOT NULL           -- isi file dalam base64
);

CREATE INDEX IF NOT EXISTS idx_rfqs_created ON rfqs(created DESC);
