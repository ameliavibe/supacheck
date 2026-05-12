export async function GET(req: Request) {
  const { data } = await supabase.auth.getUser(req.headers.get('Authorization')!);
  return Response.json({ user: data.user });
}
