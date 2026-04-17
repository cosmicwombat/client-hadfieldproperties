-- Hadfield Properties — Time Tracker schema
-- All timestamps are unix milliseconds (UTC). Render in local timezone on the client.

CREATE TABLE IF NOT EXISTS workers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  phone TEXT,
  pin_hash TEXT NOT NULL,            -- sha256(pin + salt) hex
  pin_salt TEXT NOT NULL,            -- per-worker random hex
  hourly_rate REAL,
  qb_employee_id TEXT,
  active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS jobsites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT,
  lat REAL,
  lng REAL,
  active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  qb_service_item TEXT,
  active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS time_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_id INTEGER NOT NULL REFERENCES workers(id),
  jobsite_id INTEGER REFERENCES jobsites(id),
  task_id INTEGER REFERENCES tasks(id),
  clock_in INTEGER NOT NULL,         -- unix ms
  clock_out INTEGER,                 -- null while active
  clock_in_lat REAL,
  clock_in_lng REAL,
  clock_in_accuracy REAL,
  clock_out_lat REAL,
  clock_out_lng REAL,
  clock_out_accuracy REAL,
  notes TEXT,
  edited_by_admin INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entry_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL,
  admin_email TEXT NOT NULL,
  action TEXT NOT NULL,              -- created | edited | deleted
  before_json TEXT,
  after_json TEXT,
  changed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE INDEX IF NOT EXISTS idx_entries_worker_date ON time_entries(worker_id, clock_in);
CREATE INDEX IF NOT EXISTS idx_entries_jobsite ON time_entries(jobsite_id);
CREATE INDEX IF NOT EXISTS idx_entries_open ON time_entries(clock_out) WHERE clock_out IS NULL;

-- Seed settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('company_name', 'Hadfield Properties LLC');
INSERT OR IGNORE INTO settings (key, value) VALUES ('timezone', 'America/Los_Angeles');
INSERT OR IGNORE INTO settings (key, value) VALUES ('pay_period', 'weekly');
INSERT OR IGNORE INTO settings (key, value) VALUES ('long_shift_hours', '12');

-- Seed starter jobsites
INSERT OR IGNORE INTO jobsites (id, name, address, active) VALUES (1, 'Mill Creek', '', 1);
INSERT OR IGNORE INTO jobsites (id, name, address, active) VALUES (2, 'Office', '', 1);
INSERT OR IGNORE INTO jobsites (id, name, address, active) VALUES (3, 'Shop', '', 1);

-- Seed starter task/cost codes
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (1, 'Framing', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (2, 'Drywall', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (3, 'Electrical', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (4, 'Plumbing', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (5, 'Cleanup', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (6, 'Demo', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (7, 'Punch List', 1);
INSERT OR IGNORE INTO tasks (id, name, active) VALUES (8, 'Travel', 1);
