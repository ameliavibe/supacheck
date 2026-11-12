import { afterEach, describe, expect, test, vi } from 'vitest';
import { safeFetch, SsrfBlockedError } from '../src/index.js';

// Literal public addresses, so nothing here depends on DNS.
const A = 'http://93.184.216.34';
const B = 'http://1.1.1.1';

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  hasBody: boolean;
}

/** Stubs `fetch` with one canned response per call and records each request. */
function stubFetch(responses: Response[]): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal('fetch', async (input: unknown, init: RequestInit = {}) => {
    seen.push({
      url: String(input),
      method: init.method ?? 'GET',
      headers: Object.fromEntries(new Headers(init.headers)),
      hasBody: init.body !== undefined && init.body !== null,
    });
    const next = responses.shift();
    if (!next) throw new Error('fetch called more often than the test expected');
    return next;
  });
  return seen;
}

const redirect = (status: number, location: string): Response =>
  new Response(null, { status, headers: { location } });
const ok = (): Response => new Response('done', { status: 200 });

afterEach(() => vi.unstubAllGlobals());

describe('safeFetch: redirects', () => {
  test('validates the redirect target before following it', async () => {
    const seen = stubFetch([redirect(302, 'http://127.0.0.1:8080/admin')]);
    await expect(safeFetch(`${A}/start`)).rejects.toMatchObject({ code: 'PRIVATE_IP' });
    expect(seen).toHaveLength(1);
  });

  test('resolves a relative Location against the current URL', async () => {
    const seen = stubFetch([redirect(302, '/next'), ok()]);
    await safeFetch(`${A}/start`);
    expect(seen.map((s) => s.url)).toEqual([`${A}/start`, `${A}/next`]);
  });

  test('refuses any redirect when maxRedirects is 0', async () => {
    stubFetch([redirect(302, `${A}/next`)]);
    const err = await safeFetch(`${A}/start`, {}, { maxRedirects: 0 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SsrfBlockedError);
    expect((err as SsrfBlockedError).code).toBe('TOO_MANY_REDIRECTS');
  });
});

describe('safeFetch: headers across redirects', () => {
  const credentials = {
    authorization: 'Bearer secret',
    cookie: 'session=1',
    'proxy-authorization': 'Basic abc',
    'x-trace': 'kept',
  };

  test('drops credential headers when a redirect leaves the origin', async () => {
    const seen = stubFetch([redirect(302, `${B}/landing`), ok()]);
    await safeFetch(`${A}/start`, { headers: credentials });
    expect(seen[0]!.headers).toMatchObject(credentials);
    expect(seen[1]!.headers).toEqual({ 'x-trace': 'kept' });
  });

  test('keeps them on a redirect within the same origin', async () => {
    const seen = stubFetch([redirect(307, `${A}/moved`), ok()]);
    await safeFetch(`${A}/start`, { headers: credentials });
    expect(seen[1]!.headers).toMatchObject(credentials);
  });

  test('treats another port or scheme as another origin', async () => {
    const seen = stubFetch([redirect(302, `${A}:8443/x`), ok()]);
    await safeFetch(`${A}/start`, { headers: credentials });
    expect(seen[1]!.headers).toEqual({ 'x-trace': 'kept' });
  });

  test('does not restore them when a later hop returns to the first origin', async () => {
    const seen = stubFetch([redirect(302, `${B}/bounce`), redirect(302, `${A}/back`), ok()]);
    await safeFetch(`${A}/start`, { headers: credentials });
    expect(seen[2]!.url).toBe(`${A}/back`);
    expect(seen[2]!.headers).toEqual({ 'x-trace': 'kept' });
  });

  test('does not change the headers object the caller passed', async () => {
    stubFetch([redirect(302, `${B}/landing`), ok()]);
    const headers = new Headers(credentials);
    await safeFetch(`${A}/start`, { headers });
    expect(headers.get('authorization')).toBe('Bearer secret');
  });
});

describe('safeFetch: method and body across redirects', () => {
  const post = { method: 'POST', body: '{"a":1}', headers: { 'content-type': 'application/json' } };

  test.each([301, 302, 303])('%i switches to GET and drops the body and its headers', async (status) => {
    const seen = stubFetch([redirect(status, `${A}/next`), ok()]);
    await safeFetch(`${A}/start`, post);
    expect(seen[1]).toMatchObject({ method: 'GET', hasBody: false });
    expect(seen[1]!.headers).toEqual({});
  });

  test.each([307, 308])('%i keeps the method, the body and its headers', async (status) => {
    const seen = stubFetch([redirect(status, `${A}/next`), ok()]);
    await safeFetch(`${A}/start`, post);
    expect(seen[1]).toMatchObject({
      method: 'POST',
      hasBody: true,
      headers: { 'content-type': 'application/json' },
    });
  });
});
