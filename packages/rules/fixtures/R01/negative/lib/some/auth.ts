// Not under app/api/, so out of scope even with a bare getUser() call.
export async function whoami(sb: any) {
  const { data } = await sb.auth.getUser();
  return data;
}
