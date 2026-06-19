-- Allow workplace admins to create time-off requests on behalf of employees in their workplace.

DROP POLICY IF EXISTS "time_off: insert own" ON public.time_off_requests;

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
