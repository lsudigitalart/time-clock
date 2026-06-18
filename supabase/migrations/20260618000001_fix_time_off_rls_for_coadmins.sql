-- Fix: allow co-admins (workplace_members with role='admin') to read time_off_requests
-- Previously only the workplace owner (workplaces.admin_id) could see employees' leave

DROP POLICY IF EXISTS "time_off: read own or workplace admin" ON public.time_off_requests;

CREATE POLICY "time_off: read own or workplace admin"
  ON public.time_off_requests FOR SELECT
  TO authenticated
  USING (
    auth.uid() = user_id
    OR is_workplace_admin(workplace_id)
  );

-- Also fix the UPDATE policy so co-admins can approve/deny
DROP POLICY IF EXISTS "time_off: update own pending or admin" ON public.time_off_requests;

CREATE POLICY "time_off: update own pending or admin"
  ON public.time_off_requests FOR UPDATE
  TO authenticated
  USING (
    (auth.uid() = user_id AND status = 'pending')
    OR is_workplace_admin(workplace_id)
  );
