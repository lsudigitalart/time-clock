-- ============================================================
-- Work mode on time entries (in-person vs remote)
-- ------------------------------------------------------------
-- Lets a user record whether a shift was worked in-person or
-- remotely. Existing rows stay NULL (unknown).
-- ============================================================

ALTER TABLE public.time_entries
  ADD COLUMN IF NOT EXISTS work_mode text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'time_entries_work_mode_chk'
  ) THEN
    ALTER TABLE public.time_entries
      ADD CONSTRAINT time_entries_work_mode_chk
      CHECK (work_mode IN ('in_person', 'remote'));
  END IF;
END $$;
