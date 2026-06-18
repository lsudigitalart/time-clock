-- Ensure uuid extension exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Add project_names column to time_entries
ALTER TABLE public.time_entries
  ADD COLUMN IF NOT EXISTS project_names text[] NOT NULL DEFAULT '{}'::text[];

-- Create workplace_projects table
CREATE TABLE IF NOT EXISTS public.workplace_projects (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workplace_id  uuid NOT NULL REFERENCES public.workplaces(id) ON DELETE CASCADE,
  name          text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workplace_id, name)
);

-- Enable RLS on workplace_projects
ALTER TABLE public.workplace_projects ENABLE ROW LEVEL SECURITY;

-- RLS Policy: SELECT for workplace members
CREATE POLICY "workspace_members_can_view_projects"
  ON public.workplace_projects FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.workplace_members wm
      WHERE wm.workplace_id = public.workplace_projects.workplace_id
        AND wm.user_id = auth.uid()
    )
  );

-- RLS Policy: INSERT for workspace admins
CREATE POLICY "workspace_admins_can_manage_projects"
  ON public.workplace_projects FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.workplace_members wm
      WHERE wm.workplace_id = public.workplace_projects.workplace_id
        AND wm.user_id = auth.uid()
        AND wm.role = 'admin'
    )
  );

-- RLS Policy: UPDATE for workspace admins
CREATE POLICY "workspace_admins_can_update_projects"
  ON public.workplace_projects FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM public.workplace_members wm
      WHERE wm.workplace_id = public.workplace_projects.workplace_id
        AND wm.user_id = auth.uid()
        AND wm.role = 'admin'
    )
  );

-- RLS Policy: DELETE for workspace admins
CREATE POLICY "workspace_admins_can_delete_projects"
  ON public.workplace_projects FOR DELETE
  USING (
    EXISTS (
      SELECT 1 FROM public.workplace_members wm
      WHERE wm.workplace_id = public.workplace_projects.workplace_id
        AND wm.user_id = auth.uid()
        AND wm.role = 'admin'
    )
  );
