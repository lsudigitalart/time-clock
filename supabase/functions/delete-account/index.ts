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

    // If deleting someone else, caller must be admin of the same workplace
    if (!isSelf) {
      const { data: callerMembership } = await userClient
        .from('workplace_members')
        .select('role, workplace_id')
        .eq('user_id', caller.id)
        .eq('role', 'admin')
        .maybeSingle();

      if (!callerMembership) {
        return json({ error: 'Only admins can delete other accounts' }, 403);
      }

      // Confirm target is in same workplace
      const { data: targetMembership } = await userClient
        .from('workplace_members')
        .select('workplace_id')
        .eq('user_id', targetId)
        .maybeSingle();

      if (targetMembership?.workplace_id !== callerMembership?.workplace_id) {
        return json({ error: 'Target user is not in your workplace' }, 403);
      }
    }

    // Use service role client to delete the auth user (cascades to all DB rows)
    const adminClient = createClient(supabaseUrl, serviceKey);
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
