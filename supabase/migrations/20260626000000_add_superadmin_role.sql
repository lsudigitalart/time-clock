-- ============================================================
-- Superadmin role
-- ------------------------------------------------------------
-- A superadmin is a global administrator who can:
--   * create / edit / delete ANY workplace
--   * move members between workplaces
--   * (inherits per-workplace admin rights everywhere)
--
-- A superadmin is simply a profile whose role = 'superadmin'.
-- There is no UI to self-assign this role. Grant it manually from
-- the Supabase SQL editor (a direct/service session bypasses the
-- privilege-escalation guard below):
--
--   UPDATE public.profiles SET role = 'superadmin'
--   WHERE email = 'you@example.com';
-- ============================================================


-- ── Helper: is the current user a global superadmin? ──────────
CREATE OR REPLACE FUNCTION public.is_superadmin()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = auth.uid() AND p.role = 'superadmin'
  );
$$;


-- ── Superadmins inherit admin / member rights everywhere ──────
CREATE OR REPLACE FUNCTION public.is_workplace_admin(wid uuid)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT public.is_superadmin()
  OR EXISTS (
    SELECT 1 FROM public.workplaces w WHERE w.id = wid AND w.admin_id = auth.uid()
  ) OR EXISTS (
    SELECT 1 FROM public.workplace_members m
    WHERE m.workplace_id = wid AND m.user_id = auth.uid() AND m.role = 'admin'
  );
$$;

CREATE OR REPLACE FUNCTION public.is_workplace_member(wid uuid)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT public.is_superadmin()
  OR EXISTS (
    SELECT 1 FROM public.workplaces w WHERE w.id = wid AND w.admin_id = auth.uid()
  ) OR EXISTS (
    SELECT 1 FROM public.workplace_members m
    WHERE m.workplace_id = wid AND m.user_id = auth.uid()
  );
$$;


-- ── Workplaces: superadmins can create / edit / delete any ────
DROP POLICY IF EXISTS "workplaces: insert (authenticated)" ON public.workplaces;
CREATE POLICY "workplaces: insert (authenticated)"
  ON public.workplaces FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = admin_id OR public.is_superadmin());

DROP POLICY IF EXISTS "workplaces: update by admin" ON public.workplaces;
CREATE POLICY "workplaces: update by admin"
  ON public.workplaces FOR UPDATE
  TO authenticated
  USING (auth.uid() = admin_id OR public.is_superadmin());

DROP POLICY IF EXISTS "workplaces: delete by superadmin" ON public.workplaces;
CREATE POLICY "workplaces: delete by superadmin"
  ON public.workplaces FOR DELETE
  TO authenticated
  USING (public.is_superadmin());


-- ── Privilege-escalation guard on profiles.role ───────────────
-- "profiles: update own" lets a user update their own row, and the signup
-- trigger copies role from user metadata. Without a guard, any user could
-- promote themselves to 'superadmin'. These changes ensure only an existing
-- superadmin (or a direct service-role / SQL session) can grant that role.

-- 1) Clamp the role copied from signup metadata to the allowed self-serve
--    values. (GoTrue runs this trigger with no auth.uid(), so the row-level
--    guard below cannot cover the signup path.)
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

-- 2) Block authenticated users from setting / changing role to a value they
--    are not allowed to grant. Direct SQL / service-role sessions (auth.uid()
--    is NULL) are allowed so the first superadmin can be created manually.
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
