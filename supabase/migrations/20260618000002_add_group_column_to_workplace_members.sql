-- Add group column to workplace_members (reserved keyword must be quoted)
ALTER TABLE public.workplace_members
  ADD COLUMN IF NOT EXISTS "group" text;

-- Reload PostgREST schema cache so the column is immediately usable
NOTIFY pgrst, 'reload schema';
