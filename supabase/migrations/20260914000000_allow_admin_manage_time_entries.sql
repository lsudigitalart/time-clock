-- Allow workplace admins (owner, co-admins, superadmins) to add and edit time entries
-- on behalf of employees in their workplace.
--
-- Before: INSERT was own-only, so an admin could not log a shift a worker forgot to clock.
--         UPDATE checked workplaces.admin_id directly, so co-admins and superadmins could
--         not edit entries even though the admin UI already showed them an Edit button.

DROP POLICY IF EXISTS "time_entries: insert own" ON public.time_entries;

CREATE POLICY "time_entries: insert own or workplace admin"
  ON public.time_entries FOR INSERT
  TO authenticated
  WITH CHECK (
    auth.uid() = user_id
    OR (
      is_workplace_admin(workplace_id)
      AND EXISTS (
        SELECT 1
        FROM public.workplace_members m
        WHERE m.workplace_id = public.time_entries.workplace_id
          AND m.user_id = public.time_entries.user_id
      )
    )
  );

DROP POLICY IF EXISTS "time_entries: update own or workplace admin" ON public.time_entries;

CREATE POLICY "time_entries: update own or workplace admin"
  ON public.time_entries FOR UPDATE
  TO authenticated
  USING (
    auth.uid() = user_id
    OR is_workplace_admin(workplace_id)
  );
