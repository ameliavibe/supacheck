# @supacheck/safe-fetch

A `fetch()` for URLs you did not write. It refuses to send a request to a private, loopback, link-local or cloud-metadata address, and it checks every redirect hop the same way.

```bash
npm install @supacheck/safe-fetch
```

Node 20 or later. ESM only. One dependency ([`ipaddr.js`](https://github.com/whitequark/ipaddr.js)).

## The problem

Any server route that fetches a URL supplied by a user can be pointed at your own network:

```ts
// app/api/preview/route.ts
export async function POST(req: Request) {
  const { url } = await req.json();
  const res = await fetch(url); // url = "http://169.254.169.254/latest/meta-data/"
  return new Response(await res.text());
}
```

That request leaves from inside your infrastructure, so it reaches things the caller cannot: the cloud metadata endpoint, an admin port on `localhost`, a database's HTTP interface on a private subnet. This is server-side request forgery (SSRF). Checking the hostname against a blocklist does not fix it, because a public hostname can resolve to a private address and a public URL can redirect to one.

## Use

```ts
import { safeFetch, SsrfBlockedError } from '@supacheck/safe-fetch';

export async function POST(req: Request) {
  const { url } = await req.json();
  try {
    const res = await safeFetch(url, { signal: AbortSignal.timeout(5000) });
    return new Response(await res.text());
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      return Response.json({ error: 'That URL is not allowed.' }, { status: 400 });
    }
    throw err;
  }
}
```

`safeFetch` takes the same `init` object as `fetch` and returns the same `Response`.

## What it checks

Before the first request and again before following each redirect:

| Check | Rejected with |
|---|---|
| The URL parses and is absolute | `INVALID_URL` |
| The scheme is `http:` or `https:` | `BAD_SCHEME` |
| The URL has a hostname | `NO_HOSTNAME` |
| The hostname is not `metadata.google.internal` and does not end in `.internal` or `.local` | `INTERNAL_HOST` |
| An IP-literal host is a public unicast address | `PRIVATE_IP` |
| The hostname resolves, and **every** address it resolves to is public unicast | `UNRESOLVABLE`, `PRIVATE_IP` |
| The redirect chain is no longer than `maxRedirects` | `TOO_MANY_REDIRECTS` |

"Public unicast" is decided by `ipaddr.js`, so the block covers more than the three RFC 1918 ranges:

- loopback (`127.0.0.0/8`, `::1`)
- private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and IPv6 unique-local (`fc00::/7`)
- link-local (`169.254.0.0/16`, which includes the `169.254.169.254` metadata address, and `fe80::/10`)
- carrier-grade NAT (`100.64.0.0/10`), unspecified, broadcast, multicast and reserved ranges
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`), which is unwrapped and judged as the IPv4 address it carries

Numeric spellings such as `http://2130706433/`, `http://0x7f.0.0.1/` and `http://0177.0.0.1/` are normalized by the URL parser to `127.0.0.1` before the check, so they are rejected too.

## Redirects

`fetch(url, { redirect: 'follow' })` validates nothing after the first URL: a public address can answer `302 Location: http://127.0.0.1:8080/`. `safeFetch` always sends with `redirect: 'manual'`, validates the `Location` it gets back, and only then follows it.

- At most 5 hops by default. Change it with the third argument: `safeFetch(url, init, { maxRedirects: 2 })`. Pass `0` to refuse any redirect.
- `301`, `302` and `303` switch the method to `GET` and drop the body. `307` and `308` keep both.
- A `3xx` response with no `Location` header, and a `304`, are returned as they are.

## API

### `safeFetch(url, init?, options?)`

```ts
function safeFetch(
  url: string,
  init?: RequestInit,
  options?: { maxRedirects?: number },
): Promise<Response>;
```

Throws `SsrfBlockedError` when any check fails. Network errors from the underlying `fetch` pass through unchanged. `init.redirect` is ignored.

### `assertSafeFetchUrl(url)`

```ts
function assertSafeFetchUrl(url: string): Promise<URL>;
```

Runs the checks on one URL and returns the parsed `URL`, without sending anything. Use it to validate a URL at the moment a user saves it (a webhook target, an avatar link) so they get the error then. Still call `safeFetch` when you later request it: what a hostname resolves to can change.

### `SsrfBlockedError`

```ts
class SsrfBlockedError extends Error {
  readonly code:
    | 'INVALID_URL'
    | 'NO_HOSTNAME'
    | 'BAD_SCHEME'
    | 'INTERNAL_HOST'
    | 'PRIVATE_IP'
    | 'UNRESOLVABLE'
    | 'TOO_MANY_REDIRECTS';
}
```

Branch on `code`. The `message` is safe to log; decide for yourself how much of it to show a caller, since telling an attacker which internal names resolve is its own small leak.

## What it does not do

- **DNS rebinding.** The hostname is resolved once to validate it, and `fetch` resolves it again to connect. A resolver under an attacker's control can answer with a public address the first time and a private one the second. Closing that gap needs the connection pinned to the validated address with a custom dispatcher, which this package does not do. If that is in your threat model, also block egress to private ranges at the network layer.
- **Headers on redirects.** The headers you pass in `init` are sent on every hop, including to a different origin. Do not pass `Authorization`, cookies or API keys for a URL you do not control.
- **Allowlists.** There is no option to permit a specific private address. If your server legitimately calls an internal service, call it with plain `fetch` from code that does not take the URL from a user.
- **Relative URLs.** The URL must be absolute. A path such as `/api/health` is rejected as `INVALID_URL`.
- **Other runtimes.** It uses `node:dns`, so it runs on Node, not in the browser or on edge runtimes without Node compatibility.
- **Response limits.** It sets no timeout and no size cap. Pass `signal: AbortSignal.timeout(ms)` and read the body with a limit when the URL is untrusted.

## With supacheck

[supacheck](https://github.com/ameliavibe/supacheck) rule R05 flags server-side `fetch()` calls that do not go through an SSRF-safe helper. Importing `safeFetch` from this package satisfies it.

## License

[Apache 2.0](https://github.com/ameliavibe/supacheck/blob/main/LICENSE)
