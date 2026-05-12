const STRIPE_API = 'https://api.stripe.com/v1/charges';

export async function chargeAmount(token: string) {
  // ssrf-safe: constant Stripe API URL
  const res = await fetch(STRIPE_API, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}
