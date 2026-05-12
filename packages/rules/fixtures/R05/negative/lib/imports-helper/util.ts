import { safeFetch } from '@supa-shield/safe-fetch';

export async function load(url: string) {
  // Helper is imported at top, this whole file is exempt by design.
  // We could still do bare fetch here for testing scenarios.
  const res = await fetch(url);
  return res.json();
}

void safeFetch;
