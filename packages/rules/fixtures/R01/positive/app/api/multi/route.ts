export async function GET() {
  const a = await supabase.auth.getUser();
  const b = await client.auth.getUser();
  return Response.json({ a, b });
}
