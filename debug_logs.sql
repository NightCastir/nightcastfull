PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS debug_logs (
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL, event TEXT NOT NULL, stage TEXT, method TEXT, path TEXT, origin TEXT, status INTEGER, code TEXT, message TEXT, details_json TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_debug_logs_created ON debug_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_debug_logs_request ON debug_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_debug_logs_status ON debug_logs(status);
