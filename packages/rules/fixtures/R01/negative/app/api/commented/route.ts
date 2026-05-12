export async function GET() {
  // historical reference: we used to call supabase.auth.getUser() here
  /*
   * Other places in the codebase still do auth.getUser() bare.
   */
  return Response.json({ ok: true });
}
