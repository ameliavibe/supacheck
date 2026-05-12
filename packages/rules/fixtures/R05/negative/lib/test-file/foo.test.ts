// Test files are exempt. fetch() in tests doesn't ship to production.
export async function setup() {
  return fetch('https://example.com');
}
