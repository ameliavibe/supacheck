export async function double(url: string) {
  const a = await fetch(url);
  const b = await fetch(url + '?retry=1');
  return [a, b];
}
