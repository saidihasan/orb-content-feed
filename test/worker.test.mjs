import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';
import worker, {
  authConstants,
  createSessionToken,
  derivePasswordHash,
  validateSessionToken,
} from '../worker.js';

const ORIGIN = 'https://orb.example';
const USERNAME = 'orb-admin';
const PASSWORD = 'contoh-passphrase-kuat';
const salt = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
const signingKey = Buffer.alloc(32, 7).toString('base64url');
const loginCsrf = Buffer.alloc(32, 9).toString('base64url');
let env;

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
