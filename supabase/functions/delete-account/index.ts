import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const serviceKey  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const anonKey     = Deno.env.get('SUPABASE_ANON_KEY')!;

    // Identify calling user from their JWT
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return json({ error: 'Unauthorized' }, 401);

    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user: caller }, error: authErr } = await userClient.auth.getUser();
    if (authErr || !caller) return json({ error: 'Unauthorized' }, 401);

    // Which account to delete?
    const { target_user_id } = await req.json();
    const targetId = target_user_id || caller.id;
    const isSelf = targetId === caller.id;

    const adminClient = createClient(supabaseUrl, serviceKey);

    // If deleting someone else, caller must either be a superadmin, or an
    // admin/owner of at least one workplace that also contains the target user.
    if (!isSelf) {
      // Superadmins can delete any account.
      const { data: callerProfile } = await adminClient
        .from('profiles')
        .select('role')
        .eq('id', caller.id)
        .maybeSingle();

      if (callerProfile?.role !== 'superadmin') {
        const [callerOwned, callerAdminMemberships] = await Promise.all([
          adminClient
            .from('workplaces')
            .select('id')
            .eq('admin_id', caller.id),
          adminClient
            .from('workplace_members')
            .select('workplace_id')
            .eq('user_id', caller.id)
            .eq('role', 'admin'),
        ]);

        const callerAdminWorkplaceIds = new Set<string>([
          ...((callerOwned.data || []).map((w: { id: string }) => w.id)),
          ...((callerAdminMemberships.data || []).map((m: { workplace_id: string }) => m.workplace_id)),
        ]);

        if (!callerAdminWorkplaceIds.size) {
          return json({ error: 'Only admins can delete other accounts' }, 403);
        }

        const [targetOwned, targetMemberships] = await Promise.all([
          adminClient
            .from('workplaces')
            .select('id')
            .eq('admin_id', targetId),
          adminClient
            .from('workplace_members')
            .select('workplace_id')
            .eq('user_id', targetId),
        ]);

        const targetWorkplaceIds = new Set<string>([
          ...((targetOwned.data || []).map((w: { id: string }) => w.id)),
          ...((targetMemberships.data || []).map((m: { workplace_id: string }) => m.workplace_id)),
        ]);

        const sameWorkplace = [...targetWorkplaceIds].some((wid) => callerAdminWorkplaceIds.has(wid));
        if (!sameWorkplace) {
          return json({ error: 'Target user is not in your workplace' }, 403);
        }
      }
    }

    // Use service role client to delete the auth user (cascades to all DB rows)
    const { error: deleteErr } = await adminClient.auth.admin.deleteUser(targetId);
    if (deleteErr) return json({ error: deleteErr.message }, 500);

    return json({ success: true });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
