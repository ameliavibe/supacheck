declare const client: { fetch: (url: string) => Promise<unknown> };

export async function load(url: string) {
  return await client.fetch(url);
}
