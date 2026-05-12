import { safeFetch } from '../security/ssrf';

export async function load(url: string) {
  const res = await fetch(url);
  return res.json();
}

void safeFetch;
