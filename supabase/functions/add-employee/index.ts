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

    // Verify calling user is an admin
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return json({ error: 'Unauthorized' }, 401);

    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user: caller }, error: authErr } = await userClient.auth.getUser();
    if (authErr || !caller) return json({ error: 'Unauthorized' }, 401);

    // Caller must be an admin in a workplace
    const { data: callerMembership } = await userClient
      .from('workplace_members')
      .select('role, workplace_id')
      .eq('user_id', caller.id)
      .in('role', ['admin'])
      .maybeSingle();

    if (!callerMembership) {
      return json({ error: 'Only admins can add employees' }, 403);
    }

    const { full_name, email, temp_password, role } = await req.json();
    if (!full_name || !email || !temp_password) {
      return json({ error: 'full_name, email, and temp_password are required' }, 400);
    }

    const memberRole = role === 'admin' ? 'admin' : 'member';
    const workplaceId = callerMembership.workplace_id;

    const adminClient = createClient(supabaseUrl, serviceKey);

    // Create auth user (email_confirm = true so they can log in immediately)
    const { data: newUser, error: createErr } = await adminClient.auth.admin.createUser({
      email,
      password: temp_password,
      email_confirm: true,
      user_metadata: {
        full_name,
        role: 'user',
        workplace_id: workplaceId,
      },
    });
    if (createErr) return json({ error: createErr.message }, 400);

    const uid = newUser.user.id;

    // Upsert profile
    await adminClient.from('profiles').upsert({
      id: uid,
      full_name,
      email,
      role: 'user',
    }, { onConflict: 'id' });

    // Add to workplace
    const { error: memberErr } = await adminClient.from('workplace_members').insert({
      workplace_id: workplaceId,
      user_id: uid,
      role: memberRole,
    });
    if (memberErr) return json({ error: memberErr.message }, 500);

    return json({ success: true, user_id: uid });
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
