import assert from 'node:assert/strict';
import { afterEach, before, describe, test } from 'node:test';
import worker, {
  authConstants,
  createSessionToken,
  derivePasswordHash,
  parseTikTokUrl,
  validateSessionToken,
} from '../worker.js';

const ORIGIN = 'https://orb.example';
const USERNAME = 'orb-admin';
const PASSWORD = 'contoh-passphrase-kuat';
const salt = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
const signingKey = Buffer.alloc(32, 7).toString('base64url');
const loginCsrf = Buffer.alloc(32, 9).toString('base64url');
let env;
const nativeFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = nativeFetch;
});

function rateLimiter(success = true) {
  return { async limit() { return { success }; } };
}

function assets() {
  return {
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path === '/generator.html') {
        return new Response(null, { status: 307, headers: { Location: '/generator' } });
      }
      return new Response(path === '/generator' ? '<h1>Generator</h1>' : `public:${path}`, {
        headers: { 'Content-Type': path.endsWith('.html') ? 'text/html' : 'text/plain' },
      });
    },
  };
}

function request(path, init = {}) {
  return new Request(`${ORIGIN}${path}`, init);
}

async function dispatch(path, init = {}, customEnv = env) {
  return worker.fetch(request(path, init), customEnv);
}

function loginInit(username = USERNAME, password = PASSWORD, next = '/generator.html') {
  return {
    method: 'POST',
    headers: {
      Origin: ORIGIN,
      'CF-Connecting-IP': '203.0.113.8',
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: `${authConstants.LOGIN_CSRF_COOKIE}=${loginCsrf}`,
    },
    body: new URLSearchParams({ username, password, next, csrf_token: loginCsrf }),
  };
}

function mockFetch(responders) {
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    calls.push({ input: String(input), init });
    const responder = responders.shift();
    assert.ok(responder, `Unexpected fetch to ${input}`);
    return typeof responder === 'function' ? responder(input, init) : responder;
  };
  return calls;
}

function tiktokPath(value) {
  return `/api/tiktok-thumbnail?url=${encodeURIComponent(value)}`;
}

function oembedResponse(thumbnailUrl = 'https://p16-sign-va.tiktokcdn.com/example.jpeg') {
  return new Response(JSON.stringify({
    version: '1.0',
    type: 'video',
    provider_name: 'TikTok',
    thumbnail_url: thumbnailUrl,
  }), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

before(async () => {
  const passwordHash = await derivePasswordHash(PASSWORD, salt);
  env = {
    ADMIN_USERNAME: USERNAME,
    ADMIN_PASSWORD_SALT: Buffer.from(salt).toString('base64url'),
    ADMIN_PASSWORD_HASH: Buffer.from(passwordHash).toString('base64url'),
    SESSION_SIGNING_KEY: signingKey,
    LOGIN_RATE_LIMITER: rateLimiter(),
    ASSETS: assets(),
  };
});

describe('public and protected routes', () => {
  test('public assets remain public', async () => {
    for (const path of ['/', '/latest.json', '/thumbnails/example.webp']) {
      const response = await dispatch(path);
      assert.equal(response.status, 200);
      assert.match(await response.text(), /^public:/u);
    }
  });

  test('every generator URL variant requires authentication', async () => {
    for (const path of ['/generator', '/generator/', '/generator.html']) {
      const response = await dispatch(path);
      assert.equal(response.status, 303);
      assert.equal(response.headers.get('Location'), '/login');
      assert.match(response.headers.get('Cache-Control'), /no-store/u);
    }
  });

  test('valid session opens generator with security headers', async () => {
    const token = await createSessionToken(signingKey);
    const response = await dispatch('/generator.html', {
      headers: { Cookie: `${authConstants.SESSION_COOKIE}=${token}` },
    });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '<h1>Generator</h1>');
    assert.match(response.headers.get('Cache-Control'), /no-store/u);
    assert.match(response.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/u);
    assert.match(response.headers.get('Content-Security-Policy'), /connect-src 'self' https:\/\/orb-content-feed\.saidihasan\.workers\.dev/u);
  });

  test('protected generator bypasses the static asset clean-URL redirect loop', async () => {
    const token = await createSessionToken(signingKey);
    const response = await dispatch('/generator.html', {
      headers: { Cookie: `${authConstants.SESSION_COOKIE}=${token}` },
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Location'), null);
  });

});

describe('login', () => {
  test('PBKDF2 uses the Cloudflare runtime maximum and rejects weaker settings', async () => {
    assert.equal(authConstants.PBKDF2_ITERATIONS, 100_000);
    await assert.rejects(() => derivePasswordHash(PASSWORD, salt, 99_999), /Unsafe PBKDF2 iterations/u);
  });

  test('login page issues a short-lived CSRF cookie and matching form token', async () => {
    const response = await dispatch('/login');
    assert.equal(response.status, 200);
    assert.match(response.headers.get('Set-Cookie'), /^__Host-orb_login_csrf=/u);
    assert.match(response.headers.get('Set-Cookie'), /Max-Age=600/u);
    assert.match(await response.text(), /name="csrf_token" value="[A-Za-z0-9_-]+"/u);
  });

  test('correct credentials create an eight-hour secure cookie', async () => {
    const response = await dispatch('/login', loginInit());
    assert.equal(response.status, 303);
    assert.equal(response.headers.get('Location'), '/generator.html');
    const cookie = response.headers.get('Set-Cookie');
    assert.match(cookie, /^__Host-orb_admin_session=/u);
    assert.match(cookie, /Max-Age=28800/u);
    assert.match(cookie, /HttpOnly/u);
    assert.match(cookie, /Secure/u);
    assert.match(cookie, /SameSite=Strict/u);
    assert.match(cookie, /__Host-orb_login_csrf=.*Max-Age=0/u);
  });

  test('authenticated visitor opening login is redirected to generator', async () => {
    const token = await createSessionToken(signingKey);
    const response = await dispatch('/login', {
      headers: { Cookie: `${authConstants.SESSION_COOKIE}=${token}` },
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get('Location'), '/generator.html');
  });

  test('wrong username and wrong password return the same generic response', async () => {
    const wrongUsername = await dispatch('/login', loginInit('unknown-admin', PASSWORD));
    const wrongPassword = await dispatch('/login', loginInit(USERNAME, 'password-yang-salah'));
    assert.equal(wrongUsername.status, 401);
    assert.equal(wrongPassword.status, 401);
    const normalizeCsrf = (body) => body.replace(
      /name="csrf_token" value="[A-Za-z0-9_-]+"/u,
      'name="csrf_token" value="<random>"',
    );
    assert.equal(normalizeCsrf(await wrongUsername.text()), normalizeCsrf(await wrongPassword.text()));
    assert.match(await (await dispatch('/login', loginInit(USERNAME, 'salah-lagi'))).text(), /Username atau password tidak valid\./u);
  });

  test('external next destination cannot create an open redirect', async () => {
    const response = await dispatch('/login', loginInit(USERNAME, PASSWORD, 'https://evil.example'));
    assert.equal(response.status, 303);
    assert.equal(response.headers.get('Location'), '/generator.html');
  });

  test('same-origin and content-type checks are enforced', async () => {
    const crossOrigin = loginInit();
    crossOrigin.headers.Origin = 'https://evil.example';
    assert.equal((await dispatch('/login', crossOrigin)).status, 403);

    const wrongType = loginInit();
    wrongType.headers['Content-Type'] = 'application/json';
    assert.equal((await dispatch('/login', wrongType)).status, 415);
  });

  test('missing or mismatched CSRF token is rejected', async () => {
    const missing = loginInit();
    delete missing.headers.Cookie;
    assert.equal((await dispatch('/login', missing)).status, 403);

    const mismatched = loginInit();
    mismatched.headers.Cookie = `${authConstants.LOGIN_CSRF_COOKIE}=${Buffer.alloc(32, 8).toString('base64url')}`;
    assert.equal((await dispatch('/login', mismatched)).status, 403);
  });

  test('in-app browser opaque origin requires same-origin metadata and CSRF token', async () => {
    const localRequest = new Request('http://localhost:8787/login', {
      method: 'POST',
      headers: {
        Origin: 'null',
        'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `${authConstants.LOGIN_CSRF_COOKIE}=${loginCsrf}`,
      },
      body: new URLSearchParams({ username: 'invalid-user', password: 'invalid-password', csrf_token: loginCsrf }),
    });
    assert.equal((await worker.fetch(localRequest, env)).status, 401);

    const productionRequest = request('/login', {
      method: 'POST',
      headers: {
        Origin: 'null',
        'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `${authConstants.LOGIN_CSRF_COOKIE}=${loginCsrf}`,
      },
      body: new URLSearchParams({ username: 'invalid-user', password: 'invalid-password', csrf_token: loginCsrf }),
    });
    assert.equal((await worker.fetch(productionRequest, env)).status, 401);
  });

  test('oversized login body is rejected', async () => {
    const response = await dispatch('/login', {
      method: 'POST',
      headers: {
        Origin: ORIGIN,
        'CF-Connecting-IP': '203.0.113.8',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `username=${'a'.repeat(5000)}&password=x`,
    });
    assert.equal(response.status, 415);
  });

  test('rate limiting returns 429 and Retry-After', async () => {
    const limitedEnv = { ...env, LOGIN_RATE_LIMITER: rateLimiter(false) };
    const response = await dispatch('/login', loginInit(), limitedEnv);
    assert.equal(response.status, 429);
    assert.equal(response.headers.get('Retry-After'), '60');
  });

  test('missing secrets fail closed without exposing configuration details', async () => {
    const unavailableEnv = { ASSETS: assets(), LOGIN_RATE_LIMITER: rateLimiter() };
    const generator = await dispatch('/generator.html', {}, unavailableEnv);
    assert.equal(generator.status, 303);
    assert.equal(generator.headers.get('Location'), '/login');

    const login = await dispatch('/login', loginInit(), unavailableEnv);
    assert.equal(login.status, 503);
    const body = await login.text();
    assert.match(body, /Layanan login sementara tidak tersedia\./u);
    assert.doesNotMatch(body, /ADMIN_PASSWORD|SESSION_SIGNING_KEY/u);
  });

  test('unsupported method returns 405 and Allow', async () => {
    const response = await dispatch('/login', { method: 'PUT' });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('Allow'), 'GET, POST');
  });
});

describe('TikTok thumbnail proxy', { concurrency: false }, () => {
  const canonicalUrl = 'https://www.tiktok.com/@orb.banten/video/1234567890123456789';

  test('accepts canonical and short TikTok URLs with strict host validation', () => {
    assert.deepEqual(parseTikTokUrl(canonicalUrl), {
      kind: 'canonical',
      url: canonicalUrl,
      videoId: '1234567890123456789',
    });
    assert.equal(parseTikTokUrl('https://vm.tiktok.com/ZMexample/').kind, 'short');
    assert.equal(parseTikTokUrl('https://vt.tiktok.com/ZMexample/').kind, 'short');
  });

  test('rejects fake domains, non-HTTPS URLs, unsupported paths, and credentials', () => {
    for (const value of [
      'https://www.tiktok.com.evil.example/@orb/video/1234567890123456789',
      'https://evil-tiktok.com/@orb/video/1234567890123456789',
      'http://www.tiktok.com/@orb/video/1234567890123456789',
      'https://user:pass@www.tiktok.com/@orb/video/1234567890123456789',
      'https://www.tiktok.com/@orb/photo/1234567890123456789',
      'https://vm.tiktok.com/',
    ]) assert.equal(parseTikTokUrl(value), null, value);
  });

  test('rejects an overlong URL and unsupported methods before fetching upstream', async () => {
    const calls = mockFetch([]);
    const longUrl = `https://www.tiktok.com/@orb/video/${'1'.repeat(2050)}`;
    const tooLong = await dispatch(tiktokPath(longUrl));
    assert.equal(tooLong.status, 414);
    assert.match(await tooLong.text(), /too long/u);

    const method = await dispatch(tiktokPath(canonicalUrl), { method: 'POST' });
    assert.equal(method.status, 405);
    assert.equal(method.headers.get('Allow'), 'GET, HEAD');
    assert.equal(calls.length, 0);
  });

  test('uses the fixed official oEmbed endpoint and returns a proxied image for GET', async () => {
    const calls = mockFetch([
      oembedResponse(),
      new Response('image-bytes', { headers: { 'Content-Type': 'image/jpeg', ETag: 'example-etag' } }),
    ]);
    const response = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Content-Type'), 'image/jpeg');
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), '*');
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.match(response.headers.get('Cache-Control'), /s-maxage=86400/u);
    assert.equal(await response.text(), 'image-bytes');

    const metadataUrl = new URL(calls[0].input);
    assert.equal(metadataUrl.origin + metadataUrl.pathname, 'https://www.tiktok.com/oembed');
    assert.equal(metadataUrl.searchParams.get('url'), canonicalUrl);
    assert.equal(calls[0].init.redirect, 'manual');
    assert.equal(calls[1].input, 'https://p16-sign-va.tiktokcdn.com/example.jpeg');
  });

  test('handles HEAD without returning an image body', async () => {
    const calls = mockFetch([
      oembedResponse(),
      new Response(null, { headers: { 'Content-Type': 'image/webp' } }),
    ]);
    const response = await dispatch(tiktokPath(canonicalUrl), { method: 'HEAD' });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Content-Type'), 'image/webp');
    assert.equal(await response.text(), '');
    assert.equal(calls[1].init.method, 'HEAD');
  });

  test('resolves short links manually and rejects redirects outside TikTok', async () => {
    const calls = mockFetch([
      new Response(null, { status: 302, headers: { Location: canonicalUrl } }),
      oembedResponse(),
      new Response('image', { headers: { 'Content-Type': 'image/jpeg' } }),
    ]);
    assert.equal((await dispatch(tiktokPath('https://vm.tiktok.com/ZMexample/'))).status, 200);
    assert.equal(calls[0].init.redirect, 'manual');

    const unsafeCalls = mockFetch([
      new Response(null, { status: 302, headers: { Location: 'https://evil.example/video/123' } }),
    ]);
    const unsafe = await dispatch(tiktokPath('https://vt.tiktok.com/ZMexample/'));
    assert.equal(unsafe.status, 502);
    assert.match(await unsafe.text(), /thumbnail is unavailable/u);
    assert.equal(unsafeCalls.length, 1);
  });

  test('stops resolving a short link after three redirects', async () => {
    const calls = mockFetch([
      new Response(null, { status: 302, headers: { Location: 'https://www.tiktok.com/t/first' } }),
      new Response(null, { status: 302, headers: { Location: 'https://www.tiktok.com/t/second' } }),
      new Response(null, { status: 302, headers: { Location: 'https://www.tiktok.com/t/third' } }),
    ]);
    const response = await dispatch(tiktokPath('https://vm.tiktok.com/ZMexample/'));
    assert.equal(response.status, 502);
    assert.equal(calls.length, 3);
  });

  test('returns a safe error when oEmbed fails or returns invalid JSON', async () => {
    mockFetch([new Response('upstream details', { status: 500, headers: { 'Content-Type': 'text/html' } })]);
    const failed = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(failed.status, 502);
    assert.doesNotMatch(await failed.text(), /upstream details/u);

    mockFetch([new Response('{broken', { headers: { 'Content-Type': 'application/json' } })]);
    const invalid = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(invalid.status, 502);
    assert.match(await invalid.text(), /metadata is unavailable/u);
  });

  test('rejects redirects and incomplete oEmbed metadata', async () => {
    mockFetch([new Response(null, { status: 302, headers: { Location: 'https://evil.example' } })]);
    const redirected = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(redirected.status, 502);

    mockFetch([new Response(JSON.stringify({
      thumbnail_url: 'https://p16-sign-va.tiktokcdn.com/example.jpeg',
    }), { headers: { 'Content-Type': 'application/json' } })]);
    const incomplete = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(incomplete.status, 502);
    assert.match(await incomplete.text(), /metadata is unavailable/u);
  });

  test('rejects unsafe thumbnail URLs and non-image upstream responses', async () => {
    mockFetch([oembedResponse('https://evil.example/thumbnail.jpg')]);
    const unsafe = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(unsafe.status, 502);
    assert.match(await unsafe.text(), /thumbnail is unavailable/u);

    mockFetch([
      oembedResponse(),
      new Response('<html>not an image</html>', { headers: { 'Content-Type': 'text/html' } }),
    ]);
    const wrongType = await dispatch(tiktokPath(canonicalUrl));
    assert.equal(wrongType.status, 502);
    assert.match(await wrongType.text(), /thumbnail is unavailable/u);
  });
});

describe('sessions and logout', () => {
  test('valid, expired, malformed, and tampered session tokens are distinguished safely', async () => {
    const now = 2_000_000_000;
    const valid = await createSessionToken(signingKey, now);
    const expired = await createSessionToken(signingKey, now - authConstants.SESSION_LIFETIME_SECONDS - 1);
    const tampered = `${valid.slice(0, -1)}${valid.endsWith('A') ? 'B' : 'A'}`;
    assert.equal(await validateSessionToken(valid, signingKey, now), true);
    assert.equal(await validateSessionToken(expired, signingKey, now), false);
    assert.equal(await validateSessionToken('not-a-token', signingKey, now), false);
    assert.equal(await validateSessionToken(tampered, signingKey, now), false);
  });

  test('expired, malformed, and tampered cookies cannot open generator', async () => {
    const now = Math.floor(Date.now() / 1000);
    const valid = await createSessionToken(signingKey, now);
    const values = [
      await createSessionToken(signingKey, now - authConstants.SESSION_LIFETIME_SECONDS - 1),
      'malformed',
      `${valid.slice(0, -1)}${valid.endsWith('A') ? 'B' : 'A'}`,
    ];
    for (const value of values) {
      const response = await dispatch('/generator.html', {
        headers: { Cookie: `${authConstants.SESSION_COOKIE}=${value}` },
      });
      assert.equal(response.status, 303);
      assert.equal(response.headers.get('Location'), '/login');
    }
  });

  test('logout is POST-only, same-origin, and clears the cookie', async () => {
    const getResponse = await dispatch('/api/logout');
    assert.equal(getResponse.status, 405);
    assert.equal(getResponse.headers.get('Allow'), 'POST');

    const crossOrigin = await dispatch('/api/logout', { method: 'POST', headers: { Origin: 'https://evil.example' } });
    assert.equal(crossOrigin.status, 403);

    const response = await dispatch('/api/logout', { method: 'POST', headers: { Origin: ORIGIN } });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get('Location'), '/login');
    assert.match(response.headers.get('Set-Cookie'), /Max-Age=0/u);
  });

  test('authentication responses are not cacheable', async () => {
    for (const response of [
      await dispatch('/login'),
      await dispatch('/login', loginInit(USERNAME, 'password-salah')),
      await dispatch('/generator.html'),
    ]) {
      assert.match(response.headers.get('Cache-Control'), /no-store/u);
    }
  });
});
