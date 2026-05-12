const STRIPE_API = 'https://api.stripe.com/v1/charges';

export async function chargeAmount(token: string) {
  const res = await fetch(STRIPE_API, { headers: { Authorization: `Bearer ${token}` } }); // ssrf-safe: constant Stripe API URL
  return res.json();
}
