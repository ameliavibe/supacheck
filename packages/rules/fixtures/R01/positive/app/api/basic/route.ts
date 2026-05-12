import { createServerSupabase } from '@/lib/auth';

export async function GET() {
  const supabase = await createServerSupabase();
  const { data } = await supabase.auth.getUser();
  return Response.json({ user: data.user });
}
