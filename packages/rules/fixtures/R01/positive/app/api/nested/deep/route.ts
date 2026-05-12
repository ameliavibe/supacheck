export async function POST() {
  const sb = makeSupabase();
  if (sb) {
    const result = await sb.auth.getUser();
    return Response.json(result);
  }
}
