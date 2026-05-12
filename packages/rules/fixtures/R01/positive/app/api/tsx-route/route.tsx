export async function GET() {
  const { data } = await supabase.auth.getUser();
  return new Response(JSON.stringify(data));
}
