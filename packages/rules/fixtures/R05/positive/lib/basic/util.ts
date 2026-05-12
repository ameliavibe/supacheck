export async function loadRemote(url: string) {
  const res = await fetch(url);
  return res.json();
}
