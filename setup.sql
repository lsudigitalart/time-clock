-- ============================================================
-- PunchCard — Supabase SQL Setup
-- Run this entire file in your Supabase SQL Editor
-- ============================================================


-- ── 1. EXTENSIONS ────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ── 2. TABLES ─────────────────────────────────────────────────

-- Profiles (mirrors auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id            uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name     text,
  role          text NOT NULL DEFAULT 'user',   -- 'user' | 'admin' | 'superadmin'
  email         text,
  planned_hours_per_week numeric,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Workplaces
CREATE TABLE IF NOT EXISTS public.workplaces (
  id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name            text NOT NULL,
  admin_id        uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  hours_per_week  numeric NOT NULL DEFAULT 40,
  work_address    text,
  work_lat        double precision,
  work_lng        double precision,
  work_radius_m   numeric NOT NULL DEFAULT 150,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- Workplace members (employees)
CREATE TABLE IF NOT EXISTS public.workplace_members (
  id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  workplace_id  uuid NOT NULL REFERENCES public.workplaces(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role          text NOT NULL DEFAULT 'member',  -- 'member' | 'admin'
  "group"       text,                            -- optional group/team name
  joined_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workplace_id, user_id)
);

ALTER TABLE public.workplace_members
  ADD COLUMN IF NOT EXISTS "group" text;

-- Time entries (clock in / clock out)
CREATE TABLE IF NOT EXISTS public.time_entries (
  id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id           uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  workplace_id      uuid NOT NULL REFERENCES public.workplaces(id) ON DELETE CASCADE,
  clock_in          timestamptz NOT NULL,
  clock_out         timestamptz,
  clock_in_lat      double precision,
  clock_in_lng      double precision,
  clock_in_accuracy_m numeric,
  clock_in_at_location boolean,
  auto_clockout_at  timestamptz,
  notes             text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.time_entries
  ADD COLUMN IF NOT EXISTS project_names text[] NOT NULL DEFAULT '{}'::text[];

CREATE TABLE IF NOT EXISTS public.workplace_projects (
  id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  workplace_id  uuid NOT NULL REFERENCES public.workplaces(id) ON DELETE CASCADE,
  name          text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workplace_id, name)
);

-- Time-off requests
CREATE TABLE IF NOT EXISTS public.time_off_requests (
  id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  workplace_id  uuid NOT NULL REFERENCES public.workplaces(id) ON DELETE CASCADE,
  date          date,                              -- legacy, kept for existing rows
  start_date    date NOT NULL,
  end_date      date NOT NULL,
  reason        text,
  notes         text,
  status        text NOT NULL DEFAULT 'pending',  -- 'pending' | 'approved' | 'denied'
  archived      boolean NOT NULL DEFAULT false,
  archived_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Planned shifts (user-entered schedule preferences)
CREATE TABLE IF NOT EXISTS public.planned_shifts (
  id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  workplace_id  uuid NOT NULL REFERENCES public.workplaces(id) ON DELETE CASCADE,
  shift_date    date NOT NULL,
  start_time    time NOT NULL,
  end_time      time NOT NULL,
  notes         text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, shift_date)
);


-- ── 3. AUTH TRIGGER ───────────────────────────────────────────
-- Automatically creates a profile row when a new user signs up.

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, role, email)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
    -- Only allow self-serve roles at signup; 'superadmin' must be granted
    -- manually (see guard_profile_role below).
    CASE
      WHEN COALESCE(NEW.raw_user_meta_data->>'role', 'user') IN ('user', 'admin')
        THEN NEW.raw_user_meta_data->>'role'
      ELSE 'user'
    END,
    NEW.email
  )
  ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


-- Privilege-escalation guard: only an existing superadmin (or a direct
-- service-role / SQL session where auth.uid() is NULL) may grant the
-- 'superadmin' role. Prevents users self-promoting via "profiles: update own".
CREATE OR REPLACE FUNCTION public.guard_profile_role()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  caller_is_super boolean;
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;                       -- direct SQL / service role
  END IF;

  caller_is_super := EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = auth.uid() AND p.role = 'superadmin'
  );

  IF caller_is_super THEN
    RETURN NEW;                       -- superadmins may change roles
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.role = 'superadmin' THEN
      NEW.role := 'user';
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.role IS DISTINCT FROM OLD.role THEN
      NEW.role := OLD.role;           -- non-superadmins cannot change role
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_profile_role_trg ON public.profiles;
CREATE TRIGGER guard_profile_role_trg
  BEFORE INSERT OR UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.guard_profile_role();


-- ── 4. ROW LEVEL SECURITY ─────────────────────────────────────

ALTER TABLE public.profiles            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workplaces          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workplace_members   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.time_entries        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.time_off_requests   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.planned_shifts      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workplace_projects  ENABLE ROW LEVEL SECURITY;


-- ── profiles ──────────────────────────────────────────────────

CREATE POLICY "profiles: read all (authenticated)"
  ON public.profiles FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "profiles: insert own"
  ON public.profiles FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = id);

CREATE POLICY "profiles: update own"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);


-- ── workplaces ────────────────────────────────────────────────
-- Allow anon SELECT so the sign-up page can list workplaces.

-- Helper: true if current user is a global superadmin
CREATE OR REPLACE FUNCTION is_superadmin()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'superadmin'
  );
$$;

-- Helper: true if current user is the owner OR a co-admin member of a workplace
-- (superadmins inherit admin rights on every workplace)
CREATE OR REPLACE FUNCTION is_workplace_admin(wid uuid)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT is_superadmin()
  OR EXISTS (
    SELECT 1 FROM workplaces w WHERE w.id = wid AND w.admin_id = auth.uid()
  ) OR EXISTS (
    SELECT 1 FROM workplace_members m
    WHERE m.workplace_id = wid AND m.user_id = auth.uid() AND m.role = 'admin'
  );
$$;

CREATE OR REPLACE FUNCTION is_workplace_member(wid uuid)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT is_superadmin()
  OR EXISTS (
    SELECT 1 FROM workplaces w WHERE w.id = wid AND w.admin_id = auth.uid()
  ) OR EXISTS (
    SELECT 1 FROM workplace_members m
    WHERE m.workplace_id = wid AND m.user_id = auth.uid()
  );
$$;

CREATE POLICY "workplaces: read all"
  ON public.workplaces FOR SELECT
  USING (true);

CREATE POLICY "workplaces: insert (authenticated)"
  ON public.workplaces FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = admin_id OR is_superadmin());

CREATE POLICY "workplaces: update by admin"
  ON public.workplaces FOR UPDATE
  TO authenticated
  USING (auth.uid() = admin_id OR is_superadmin());

CREATE POLICY "workplaces: delete by superadmin"
  ON public.workplaces FOR DELETE
  TO authenticated
  USING (is_superadmin());


-- ── workplace_members ─────────────────────────────────────────

-- A user can see their own memberships; a workplace admin can see all members of their workplace.
CREATE POLICY "workplace_members: read own or admin"
  ON public.workplace_members FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id OR is_workplace_admin(workplace_id));

CREATE POLICY "workplace_members: insert own or admin"
  ON public.workplace_members FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id OR is_workplace_admin(workplace_id));

CREATE POLICY "workplace_members: update by admin"
  ON public.workplace_members FOR UPDATE
  TO authenticated
  USING (is_workplace_admin(workplace_id));

CREATE POLICY "workplace_members: delete by admin or self"
  ON public.workplace_members FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id OR is_workplace_admin(workplace_id));


-- ── workplace_projects ───────────────────────────────────────

CREATE POLICY "workplace_projects: read by workplace member"
  ON public.workplace_projects FOR SELECT
  TO authenticated
  USING (is_workplace_member(workplace_id));

CREATE POLICY "workplace_projects: insert by admin"
  ON public.workplace_projects FOR INSERT
  TO authenticated
  WITH CHECK (is_workplace_admin(workplace_id));

CREATE POLICY "workplace_projects: update by admin"
  ON public.workplace_projects FOR UPDATE
  TO authenticated
  USING (is_workplace_admin(workplace_id));

CREATE POLICY "workplace_projects: delete by admin"
  ON public.workplace_projects FOR DELETE
  TO authenticated
  USING (is_workplace_admin(workplace_id));


-- ── time_entries ──────────────────────────────────────────────

-- Users can see their own entries; admins can see all entries in their workplace.
CREATE POLICY "time_entries: read own or workplace admin"
  ON public.time_entries FOR SELECT
  TO authenticated
  USING (
    auth.uid() = user_id
    OR EXISTS (
      SELECT 1 FROM public.workplaces w
      WHERE w.id = workplace_id AND w.admin_id = auth.uid()
    )
  );

CREATE POLICY "time_entries: insert own"
  ON public.time_entries FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "time_entries: update own or workplace admin"
  ON public.time_entries FOR UPDATE
  TO authenticated
  USING (
    auth.uid() = user_id
    OR EXISTS (
      SELECT 1 FROM public.workplaces w
      WHERE w.id = workplace_id AND w.admin_id = auth.uid()
    )
  );

CREATE POLICY "time_entries: delete own"
  ON public.time_entries FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);


-- ── time_off_requests ─────────────────────────────────────────

CREATE POLICY "time_off: read own or workplace admin"
  ON public.time_off_requests FOR SELECT
  TO authenticated
  USING (
    auth.uid() = user_id
    OR EXISTS (
      SELECT 1 FROM public.workplaces w
      WHERE w.id = workplace_id AND w.admin_id = auth.uid()
    )
  );

CREATE POLICY "time_off: insert own or workplace admin"
  ON public.time_off_requests FOR INSERT
  TO authenticated
  WITH CHECK (
    (
      auth.uid() = user_id
      AND (
        EXISTS (
          SELECT 1
          FROM public.workplaces w
          WHERE w.id = public.time_off_requests.workplace_id
            AND w.admin_id = auth.uid()
        )
        OR EXISTS (
          SELECT 1
          FROM public.workplace_members m
          WHERE m.workplace_id = public.time_off_requests.workplace_id
            AND m.user_id = auth.uid()
        )
      )
    )
    OR (
      is_workplace_admin(workplace_id)
      AND EXISTS (
        SELECT 1
        FROM public.workplace_members m
        WHERE m.workplace_id = public.time_off_requests.workplace_id
          AND m.user_id = public.time_off_requests.user_id
      )
    )
  );

-- Admins can update status (approve/deny); users can update their own pending requests.
CREATE POLICY "time_off: update own pending or admin"
  ON public.time_off_requests FOR UPDATE
  TO authenticated
  USING (
    (auth.uid() = user_id AND status = 'pending')
    OR EXISTS (
      SELECT 1 FROM public.workplaces w
      WHERE w.id = workplace_id AND w.admin_id = auth.uid()
    )
  );

CREATE POLICY "time_off: delete own pending"
  ON public.time_off_requests FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id AND status = 'pending');


-- ── planned_shifts ──────────────────────────────────────────

CREATE POLICY "planned_shifts: read own or workplace admin"
  ON public.planned_shifts FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id OR is_workplace_admin(workplace_id));

CREATE POLICY "planned_shifts: insert own"
  ON public.planned_shifts FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "planned_shifts: update own"
  ON public.planned_shifts FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "planned_shifts: delete own"
  ON public.planned_shifts FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);


-- ── 5. HELPFUL INDEXES ────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_time_entries_user     ON public.time_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_workplace ON public.time_entries(workplace_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_clock_in  ON public.time_entries(clock_in);
CREATE INDEX IF NOT EXISTS idx_time_off_user          ON public.time_off_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_time_off_workplace     ON public.time_off_requests(workplace_id);
CREATE INDEX IF NOT EXISTS idx_time_off_archived      ON public.time_off_requests(archived);
CREATE INDEX IF NOT EXISTS idx_planned_shifts_user     ON public.planned_shifts(user_id);
CREATE INDEX IF NOT EXISTS idx_wm_user                ON public.workplace_members(user_id);
CREATE INDEX IF NOT EXISTS idx_wm_workplace           ON public.workplace_members(workplace_id);


-- ── Done! ─────────────────────────────────────────────────────
-- All tables, RLS policies, indexes, and the auth trigger are set up.
-- Next steps:
--   1. Fill in SB_URL and SB_KEY in index.html
--   2. Push index.html to GitHub and enable GitHub Pages
--   3. In Supabase → Authentication → URL Configuration, add your GitHub Pages URL
--      as a Redirect URL and set it as the Site URL.