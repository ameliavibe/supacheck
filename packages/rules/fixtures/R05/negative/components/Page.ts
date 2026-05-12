// Not under lib/ or app/api/, so out of scope even with a bare fetch().
export async function load(url: string) {
  return fetch(url);
}
