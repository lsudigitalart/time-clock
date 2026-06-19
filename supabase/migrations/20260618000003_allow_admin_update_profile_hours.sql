-- Allow workplace admins to update profile rows for users in their workplace.
-- Needed for admin target-hour overrides (profiles.planned_hours_per_week).

DROP POLICY IF EXISTS "profiles: update by workplace admin" ON public.profiles;

CREATE POLICY "profiles: update by workplace admin"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1
      FROM public.workplace_members t
      WHERE t.user_id = public.profiles.id
        AND is_workplace_admin(t.workplace_id)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM public.workplace_members t
      WHERE t.user_id = public.profiles.id
        AND is_workplace_admin(t.workplace_id)
    )
  );
