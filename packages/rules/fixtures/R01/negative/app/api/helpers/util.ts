// This file is inside app/api/ but is not a route.ts/.tsx, so it's out of scope.
// A bare getUser() here would not be flagged (helpers are out-of-scope by design).
export async function loadCurrentUser(sb: any) {
  const { data } = await sb.auth.getUser();
  return data.user;
}
