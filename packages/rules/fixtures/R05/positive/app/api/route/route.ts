export async function POST(req: Request) {
  const { url } = await req.json();
  const upstream = await fetch(url);
  return Response.json(await upstream.json());
}
