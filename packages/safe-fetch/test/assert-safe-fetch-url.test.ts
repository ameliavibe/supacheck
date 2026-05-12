import { describe, expect, test } from 'vitest';
import { assertSafeFetchUrl, SsrfBlockedError } from '../src/index.js';

async function expectBlocked(url: string, code: string): Promise<void> {
  try {
    await assertSafeFetchUrl(url);
    throw new Error(`expected ${url} to be blocked but it was allowed`);
  } catch (err) {
    expect(err).toBeInstanceOf(SsrfBlockedError);
    expect((err as SsrfBlockedError).code).toBe(code);
  }
}

describe('assertSafeFetchUrl: scheme + parse', () => {
  test('rejects garbage', async () => {
    await expectBlocked('not a url', 'INVALID_URL');
  });

  test('rejects file:// scheme', async () => {
    await expectBlocked('file:///etc/passwd', 'BAD_SCHEME');
  });

  test('rejects gopher:// scheme', async () => {
    await expectBlocked('gopher://localhost/', 'BAD_SCHEME');
  });

  test('rejects javascript: scheme', async () => {
    await expectBlocked('javascript:alert(1)', 'BAD_SCHEME');
  });
});

describe('assertSafeFetchUrl: literal IP addresses', () => {
  test('rejects loopback IPv4', async () => {
    await expectBlocked('http://127.0.0.1/', 'PRIVATE_IP');
  });

  test('rejects loopback IPv6', async () => {
    await expectBlocked('http://[::1]/', 'PRIVATE_IP');
  });

  test('rejects RFC1918 10/8', async () => {
    await expectBlocked('http://10.0.0.5/', 'PRIVATE_IP');
  });

  test('rejects RFC1918 192.168/16', async () => {
    await expectBlocked('http://192.168.1.1/', 'PRIVATE_IP');
  });

  test('rejects RFC1918 172.16/12', async () => {
    await expectBlocked('http://172.16.0.1/', 'PRIVATE_IP');
  });

  test('rejects link-local 169.254/16 (cloud metadata)', async () => {
    await expectBlocked('http://169.254.169.254/latest/meta-data/', 'PRIVATE_IP');
  });

  test('rejects IPv4-mapped IPv6 form of loopback', async () => {
    await expectBlocked('http://[::ffff:127.0.0.1]/', 'PRIVATE_IP');
  });

  test('rejects IPv6 link-local fe80::', async () => {
    await expectBlocked('http://[fe80::1]/', 'PRIVATE_IP');
  });
});

describe('assertSafeFetchUrl: hostnames', () => {
  test('rejects metadata.google.internal by name', async () => {
    await expectBlocked('http://metadata.google.internal/', 'INTERNAL_HOST');
  });

  test('rejects *.internal by name', async () => {
    await expectBlocked('http://something.internal/', 'INTERNAL_HOST');
  });

  test('rejects *.local by name', async () => {
    await expectBlocked('http://printer.local/', 'INTERNAL_HOST');
  });
});

describe('assertSafeFetchUrl: allows public addresses', () => {
  // We avoid hitting DNS for arbitrary hostnames in unit tests; use a public
  // literal IP instead. 1.1.1.1 has been Cloudflare DNS since 2018.
  test('allows public literal IPv4', async () => {
    const url = await assertSafeFetchUrl('https://1.1.1.1/');
    expect(url.toString()).toBe('https://1.1.1.1/');
  });

  test('allows public literal IPv6', async () => {
    // 2606:4700:4700::1111 is Cloudflare DNS.
    const url = await assertSafeFetchUrl('https://[2606:4700:4700::1111]/');
    expect(url.toString()).toBe('https://[2606:4700:4700::1111]/');
  });
});
