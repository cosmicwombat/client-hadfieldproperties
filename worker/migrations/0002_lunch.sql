-- Hadfield Properties — Time Tracker migration 0002
-- Adds 4-punch-per-day support (in / lunch_out / lunch_in / out) and
-- worker self-edit + end-of-day lock.
--
-- Apply locally:
--   wrangler d1 execute hadfield-db --file=migrations/0002_lunch.sql --local
-- Apply remote (production):
--   wrangler d1 execute hadfield-db --file=migrations/0002_lunch.sql --remote
--
-- Safe to run more than once on a fresh DB (IF NOT EXISTS / OR IGNORE). D1/SQLite
-- ALTER TABLE does NOT support IF NOT EXISTS on columns, so rerunning on a DB
-- that already has these columns will error with "duplicate column name" — that
-- is expected and harmless; it means the column already exists.

-- New columns on time_entries:
--   lunch_out           — unix ms when worker left for lunch (nullable)
--   lunch_in            — unix ms when worker came back from lunch (nullable)
--   lunch_out_lat/lng/accuracy — GPS captured at lunch_out punch
--   lunch_in_lat/lng/accuracy  — GPS captured at lunch_in punch
--   worker_finished_day — unix ms when worker tapped "Finish Day" (nullable; null = still editable by worker)
--   edited_by_worker    — 1 if worker self-edited any time on this row

ALTER TABLE time_entries ADD COLUMN lunch_out INTEGER;
ALTER TABLE time_entries ADD COLUMN lunch_in  INTEGER;
ALTER TABLE time_entries ADD COLUMN lunch_out_lat REAL;
ALTER TABLE time_entries ADD COLUMN lunch_out_lng REAL;
ALTER TABLE time_entries ADD COLUMN lunch_out_accuracy REAL;
ALTER TABLE time_entries ADD COLUMN lunch_in_lat REAL;
ALTER TABLE time_entries ADD COLUMN lunch_in_lng REAL;
ALTER TABLE time_entries ADD COLUMN lunch_in_accuracy REAL;
ALTER TABLE time_entries ADD COLUMN worker_finished_day INTEGER;
ALTER TABLE time_entries ADD COLUMN edited_by_worker INTEGER DEFAULT 0;

-- Index to speed up "what is this worker's currently-editable day row?" lookups.
CREATE INDEX IF NOT EXISTS idx_entries_worker_unfinished
  ON time_entries(worker_id, clock_in)
  WHERE worker_finished_day IS NULL;

-- --------------------------------------------------------------------------
-- Data-safety backfill for existing rows
-- --------------------------------------------------------------------------
-- Without this, every pre-migration row would be "unfinished" from the
-- worker's perspective and would (a) show up on their review screen, and
-- (b) block them from clocking in tomorrow ("you have an unfinished day").
--
-- Rule:
--   - If the row is already completed (clock_out IS NOT NULL), mark it as
--     finished by setting worker_finished_day = clock_out. That hides it
--     from the worker's review screen while preserving every single value
--     in the row exactly as it was — no data is altered, only the new
--     "lock" flag is populated.
--   - If the row is still open (clock_out IS NULL), LEAVE IT ALONE. These
--     are "forgot to clock out" rows that admin already needs to resolve.
--
-- Idempotent: the WHERE filter means this only touches rows that haven't
-- already been backfilled, so re-running the migration is harmless.

UPDATE time_entries
   SET worker_finished_day = clock_out
 WHERE clock_out IS NOT NULL
   AND worker_finished_day IS NULL;
