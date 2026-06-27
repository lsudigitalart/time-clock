-- ============================================================
-- Allow superadmins to manage user roles
-- ------------------------------------------------------------
-- Superadmins can update any profile row, including the `role`
-- column, so they can promote/demote users between
-- 'user' (regular member), 'admin', and 'superadmin'.
--
-- The guard_profile_role trigger (see 20260626000000) already
-- permits an existing superadmin to change role values; this
-- migration adds the row-level policy that lets a superadmin
-- target ANY profile row (not just members of their workplaces).
-- ============================================================

DROP POLICY IF EXISTS "profiles: update by superadmin" ON public.profiles;
CREATE POLICY "profiles: update by superadmin"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (public.is_superadmin())
  WITH CHECK (public.is_superadmin());
