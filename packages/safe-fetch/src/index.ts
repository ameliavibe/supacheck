/**
 * @supacheck/safe-fetch
 *
 * Drop-in replacement for the global `fetch()` that:
 *
 *   1. Rejects non-http(s) schemes.
 *   2. Resolves the hostname via DNS (catches hostnames that point at
 *      private IPs, e.g. attacker.com resolving to 169.254.169.254).
 *   3. Parses every resolved address through ipaddr.js, including
 *      octal/decimal/hex IPv4 forms, IPv4-mapped-IPv6 (`::ffff:127.0.0.1`),
 *      and IPv6 link-local / unique-local / loopback ranges.
 *   4. Rejects any address whose ipaddr.js range() is anything other than
 *      `unicast` (or `ipv4Mapped`-of-unicast).
 *
 * For redirect-following callers, prefer `safeFetch()` over a bare
 * `fetch(url, { redirect: 'follow' })`. `fetch`'s auto-follow validates only
 * the input URL: a 302 chain `public -> 127.0.0.1:8080 -> public` would land
 * the request on a private IP between hops without us seeing it. `safeFetch`
 * does manual redirect handling and validates each `Location` header before
 * following.
 *
 * Note on DNS rebinding: this helper validates DNS at validation time, but
 * the subsequent `fetch` resolves DNS again, so a hostile resolver could
 * answer with a public IP at validation time and a private IP at fetch time.
 * Full rebinding immunity requires pinning the connection to a resolved IP
 * via a custom dispatcher. Out of scope here.
 */

import * as dnsModule from 'node:dns';
import ipaddr from 'ipaddr.js';

const SAFE_RANGES = new Set(['unicast']);

function isAddressSafe(addr: ipaddr.IPv4 | ipaddr.IPv6): boolean {
  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) {
      return SAFE_RANGES.has(v6.toIPv4Address().range());
    }
    return SAFE_RANGES.has(v6.range());
  }
  return SAFE_RANGES.has((addr as ipaddr.IPv4).range());
}

export type SsrfBlockedCode =
  | 'INVALID_URL'
  | 'NO_HOSTNAME'
  | 'BAD_SCHEME'
  | 'INTERNAL_HOST'
  | 'PRIVATE_IP'
  | 'UNRESOLVABLE'
  | 'TOO_MANY_REDIRECTS';

export class SsrfBlockedError extends Error {
  readonly code: SsrfBlockedCode;
  constructor(code: SsrfBlockedCode, reason: string) {
    super(reason);
    this.name = 'SsrfBlockedError';
    this.code = code;
  }
}

export async function assertSafeFetchUrl(rawUrl: string): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError('INVALID_URL', 'Invalid URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfBlockedError('BAD_SCHEME', `URL scheme "${parsed.protocol}" is not allowed`);
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) throw new SsrfBlockedError('NO_HOSTNAME', 'URL has no hostname');

  if (
    hostname === 'metadata.google.internal' ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local')
  ) {
    throw new SsrfBlockedError('INTERNAL_HOST', 'URLs pointing to internal hosts are not allowed');
  }

  if (ipaddr.isValid(hostname)) {
    const addr = ipaddr.parse(hostname);
    if (!isAddressSafe(addr)) {
      throw new SsrfBlockedError(
        'PRIVATE_IP',
        'URLs pointing to private/internal networks are not allowed',
      );
    }
    return parsed;
  }

  let records: dnsModule.LookupAddress[];
  try {
    records = await dnsModule.promises.lookup(hostname, { all: true });
  } catch {
    throw new SsrfBlockedError('UNRESOLVABLE', 'Could not resolve URL hostname');
  }
  if (records.length === 0) {
    throw new SsrfBlockedError('UNRESOLVABLE', 'Could not resolve URL hostname');
  }
  for (const rec of records) {
    if (!ipaddr.isValid(rec.address)) {
      throw new SsrfBlockedError('PRIVATE_IP', 'Resolved hostname to an unparseable address');
    }
    const addr = ipaddr.parse(rec.address);
    if (!isAddressSafe(addr)) {
      throw new SsrfBlockedError(
        'PRIVATE_IP',
        'URLs pointing to private/internal networks are not allowed',
      );
    }
  }
  return parsed;
}

const DEFAULT_MAX_REDIRECTS = 5;

// What `fetch` itself drops when a redirect leaves the origin or stops sending a body.
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'proxy-authorization'];
const BODY_HEADERS = [
  'content-encoding',
  'content-language',
  'content-length',
  'content-location',
  'content-type',
];

export interface SafeFetchOptions {
  /** Cap on redirect chain length (default 5). */
  maxRedirects?: number;
}

export async function safeFetch(
  rawUrl: string,
  init: RequestInit = {},
  opts: SafeFetchOptions = {},
): Promise<Response> {
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let current = await assertSafeFetchUrl(rawUrl);
  let method = (init.method ?? 'GET').toUpperCase();
  let body = init.body;
  const headers = new Headers(init.headers);

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const res = await fetch(current, { ...init, method, body, headers, redirect: 'manual' });
    if (res.status < 300 || res.status >= 400 || res.status === 304) return res;
    const location = res.headers.get('location');
    if (!location) return res;

    if (hop === maxRedirects) {
      throw new SsrfBlockedError(
        'TOO_MANY_REDIRECTS',
        `Exceeded maximum ${maxRedirects} redirects`,
      );
    }
    const next = await assertSafeFetchUrl(new URL(location, current).toString());

    // Credentials were given for the origin the caller named, not for wherever
    // it redirects. Once dropped they stay dropped, even if a later hop returns.
    if (next.origin !== current.origin) {
      for (const name of CREDENTIAL_HEADERS) headers.delete(name);
    }
    if (res.status === 301 || res.status === 302 || res.status === 303) {
      method = 'GET';
      body = undefined;
      for (const name of BODY_HEADERS) headers.delete(name);
    }
    current = next;
  }

  throw new SsrfBlockedError('TOO_MANY_REDIRECTS', `Exceeded maximum ${maxRedirects} redirects`);
}
