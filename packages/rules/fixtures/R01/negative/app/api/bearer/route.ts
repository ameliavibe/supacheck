export async function GET(req: Request) {
  const token = req.headers.get('authorization')?.replace('Bearer ', '');
  const { data } = await supabase.auth.getUser(token!);
  return Response.json({ user: data.user });
}
