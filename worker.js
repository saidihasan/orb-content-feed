const INSTAGRAM_CODE = /^[A-Za-z0-9_-]{5,30}$/;
const TIKTOK_URL_MAX_LENGTH = 2048;
const TIKTOK_REDIRECT_LIMIT = 3;
const TIKTOK_OEMBED_ENDPOINT = 'https://www.tiktok.com/oembed';
const TIKTOK_CANONICAL_HOSTS = new Set(['tiktok.com', 'www.tiktok.com', 'm.tiktok.com']);
const TIKTOK_SHORT_HOSTS = new Set(['vm.tiktok.com', 'vt.tiktok.com']);
const TIKTOK_THUMBNAIL_HOST_ROOTS = ['tiktokcdn.com', 'tiktokcdn-us.com', 'tiktokcdn-eu.com'];
const GENERATOR_PATHS = new Set(['/generator', '/generator/', '/generator.html']);
const SESSION_COOKIE = '__Host-orb_admin_session';
const LOGIN_CSRF_COOKIE = '__Host-orb_login_csrf';
const SESSION_LIFETIME_SECONDS = 8 * 60 * 60;
const LOGIN_CSRF_LIFETIME_SECONDS = 10 * 60;
// Cloudflare workerd caps PBKDF2 at 100,000 iterations to limit request-level DoS.
const PBKDF2_ITERATIONS = 100_000;
const MAX_LOGIN_BODY_BYTES = 4096;
const MAX_USERNAME_LENGTH = 128;
const MAX_PASSWORD_LENGTH = 1024;
const PRODUCTION_ORIGIN = 'https://orb-content-feed.saidihasan.workers.dev';
const encoder = new TextEncoder();

const AUTH_HEADERS = {
  'Cache-Control': 'no-store, max-age=0',
  Pragma: 'no-cache',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};

const LOGIN_CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');

const GENERATOR_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' https: data:",
  `connect-src 'self' ${PRODUCTION_ORIGIN}`,
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

function withHeaders(headers, additions) {
  const result = new Headers(headers);
  for (const [name, value] of Object.entries(additions)) result.set(name, value);
  return result;
}

function authHeaders(csp = LOGIN_CSP) {
  return { ...AUTH_HEADERS, 'Content-Security-Policy': csp };
}

function errorResponse(message, status) {
  return Response.json(
    { error: message },
    {
      status,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    },
  );
}

function publicApiError(request, message, status, allowedMethods) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
  };
  if (allowedMethods) headers.Allow = allowedMethods.join(', ');
  const body = request.method === 'HEAD' ? null : JSON.stringify({ error: message });
  return new Response(body, { status, headers });
}

function methodNotAllowed(allowed, protectedRoute = true) {
  const headers = protectedRoute ? authHeaders() : { 'Cache-Control': 'no-store' };
  return new Response(null, {
    status: 405,
    headers: { ...headers, Allow: allowed.join(', ') },
  });
}

function redirect(location, status = 303) {
  return new Response(null, {
    status,
    headers: { ...authHeaders(), Location: location },
  });
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64UrlToBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error('Invalid encoding');
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytesToBase64Url(bytes) !== value) throw new Error('Non-canonical encoding');
  return bytes;
}

function fixedTimeEqual(left, right) {
  if (!(left instanceof Uint8Array)) left = new Uint8Array(left);
  if (!(right instanceof Uint8Array)) right = new Uint8Array(right);
  if (left.byteLength !== right.byteLength) return false;
  if (typeof crypto.subtle.timingSafeEqual === 'function') {
    return crypto.subtle.timingSafeEqual(left, right);
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}

export async function derivePasswordHash(password, salt, iterations = PBKDF2_ITERATIONS) {
  if (!Number.isInteger(iterations) || iterations < PBKDF2_ITERATIONS) throw new Error('Unsafe PBKDF2 iterations');
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

function validAuthSecrets(env) {
  return ['ADMIN_USERNAME', 'ADMIN_PASSWORD_SALT', 'ADMIN_PASSWORD_HASH', 'SESSION_SIGNING_KEY']
    .every((name) => typeof env[name] === 'string' && env[name].length > 0);
}

async function verifyCredentials(username, password, env) {
  if (!validAuthSecrets(env)) return false;
  try {
    const [candidateUsername, configuredUsername] = await Promise.all([
      sha256(username),
      sha256(env.ADMIN_USERNAME),
    ]);
    const candidateHash = await derivePasswordHash(password, base64UrlToBytes(env.ADMIN_PASSWORD_SALT));
    const configuredHash = base64UrlToBytes(env.ADMIN_PASSWORD_HASH);
    const usernameMatches = fixedTimeEqual(candidateUsername, configuredUsername);
    const passwordMatches = fixedTimeEqual(candidateHash, configuredHash);
    return usernameMatches && passwordMatches;
  } catch {
    return false;
  }
}

async function importSessionKey(value) {
  return crypto.subtle.importKey(
    'raw',
    base64UrlToBytes(value),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

export async function createSessionToken(signingKey, nowSeconds = Math.floor(Date.now() / 1000)) {
  const payload = encoder.encode(JSON.stringify({
    v: 1,
    iat: nowSeconds,
    exp: nowSeconds + SESSION_LIFETIME_SECONDS,
  }));
  const encodedPayload = bytesToBase64Url(payload);
  const key = await importSessionKey(signingKey);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(encodedPayload));
  return `${encodedPayload}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

export async function validateSessionToken(token, signingKey, nowSeconds = Math.floor(Date.now() / 1000)) {
  try {
    if (typeof token !== 'string' || token.length > 1024) return false;
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [encodedPayload, encodedSignature] = parts;
    const signature = base64UrlToBytes(encodedSignature);
    const key = await importSessionKey(signingKey);
    const validSignature = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(encodedPayload));
    if (!validSignature) return false;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encodedPayload)));
    return payload?.v === 1
      && Number.isInteger(payload.iat)
      && Number.isInteger(payload.exp)
      && payload.exp - payload.iat === SESSION_LIFETIME_SECONDS
      && payload.iat <= nowSeconds + 60
      && payload.exp > nowSeconds;
  } catch {
    return false;
  }
}

function cookieValue(request, name) {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  const matches = header.split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`));
  if (matches.length !== 1) return null;
  return matches[0].slice(name.length + 1) || null;
}

async function hasValidSession(request, env) {
  if (!validAuthSecrets(env)) return false;
  const token = cookieValue(request, SESSION_COOKIE);
  return token ? validateSessionToken(token, env.SESSION_SIGNING_KEY) : false;
}

function setSessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Max-Age=${SESSION_LIFETIME_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function createLoginCsrfToken() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function setLoginCsrfCookie(token) {
  return `${LOGIN_CSRF_COOKIE}=${token}; Max-Age=${LOGIN_CSRF_LIFETIME_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function clearLoginCsrfCookie() {
  return `${LOGIN_CSRF_COOKIE}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function validLoginCsrf(request, formToken) {
  try {
    const cookieToken = cookieValue(request, LOGIN_CSRF_COOKIE);
    if (!cookieToken || typeof formToken !== 'string') return false;
    return fixedTimeEqual(base64UrlToBytes(cookieToken), base64UrlToBytes(formToken));
  } catch {
    return false;
  }
}

function loginPage({ error = '', status = 200, next = '/generator.html', csrfToken } = {}) {
  const alert = error ? `<div class="alert" role="alert">${error}</div>` : '';
  const safeNext = GENERATOR_PATHS.has(next) ? next : '/generator.html';
  const body = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Login administrator ORB Content Feed.">
  <title>Login Admin · ORB</title>
  <style>
    :root{--ink:#172033;--muted:#647084;--line:#dce2ea;--soft:#f4f6f9;--red:#a61f2b;--navy:#17355f;--danger:#b42318}*{box-sizing:border-box}body{display:grid;min-height:100vh;margin:0;padding:24px;place-items:center;background:radial-gradient(circle at 90% 0,#f9e6d2 0,transparent 30rem),var(--soft);color:var(--ink);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{width:min(100%,420px)}.brand{display:flex;align-items:center;justify-content:center;gap:11px;margin-bottom:20px;text-decoration:none;color:inherit;font-weight:800}.brand-mark{display:grid;width:38px;height:38px;place-items:center;border-radius:12px;background:linear-gradient(145deg,var(--red),#dc5041);color:#fff}.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:.08em}.card{padding:30px;border:1px solid var(--line);border-radius:20px;background:#fff;box-shadow:0 20px 60px #2036561a}h1{margin:0;font:800 34px/1.08 Georgia,serif;letter-spacing:-.02em}.lead{margin:10px 0 24px;color:var(--muted)}label{display:block;margin:14px 0 6px;font-size:12px;font-weight:800}input{display:block;width:100%;min-height:46px;padding:10px 12px;border:1px solid #cbd3df;border-radius:10px;background:#fff;color:var(--ink);font:inherit;outline:none}input:focus{border-color:#5175a4;box-shadow:0 0 0 3px #5175a422}button{width:100%;min-height:46px;margin-top:20px;border:1px solid var(--navy);border-radius:10px;background:var(--navy);color:#fff;font:750 15px system-ui;cursor:pointer}.alert{margin:0 0 18px;padding:11px 12px;border:1px solid #f0b7b2;border-radius:10px;background:#fff1f0;color:var(--danger);font-size:13px}.back{display:block;margin-top:18px;color:var(--muted);font-size:13px;text-align:center;text-underline-offset:3px}@media(max-width:480px){.card{padding:24px}}
  </style>
</head>
<body>
  <main class="shell">
    <a class="brand" href="/"><span class="brand-mark">O</span><span>ORB Content Feed<small>ADMIN · BIRO ORGANISASI BANTEN</small></span></a>
    <section class="card" aria-labelledby="login-title">
      <h1 id="login-title">Masuk ke generator</h1>
      <p class="lead">Gunakan akun administrator untuk melanjutkan.</p>
      ${alert}
      <form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="${csrfToken}">
        <input type="hidden" name="next" value="${safeNext}">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" maxlength="128" autocomplete="username" required autofocus>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" maxlength="1024" autocomplete="current-password" required>
        <button type="submit">Masuk</button>
      </form>
    </section>
    <a class="back" href="/">Kembali ke halaman publik</a>
  </main>
</body>
</html>`;
  return new Response(body, {
    status,
    headers: { ...authHeaders(), 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function freshLoginPage(options = {}) {
  const csrfToken = createLoginCsrfToken();
  const response = loginPage({ ...options, csrfToken });
  response.headers.set('Set-Cookie', setLoginCsrfCookie(csrfToken));
  return response;
}

function requestedNext(url, formValue = '') {
  const candidate = formValue || url.searchParams.get('next') || '';
  return GENERATOR_PATHS.has(candidate) ? candidate : '/generator.html';
}

function sameOrigin(request) {
  const origin = request.headers.get('Origin');
  const url = new URL(request.url);
  if (origin === url.origin) return true;
  return origin === 'null'
    && request.headers.get('Sec-Fetch-Site') === 'same-origin';
}

async function readLoginForm(request) {
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') return null;
  const lengthHeader = request.headers.get('Content-Length');
  const declaredLength = lengthHeader === null ? 0 : Number(lengthHeader);
  if (!Number.isFinite(declaredLength) || declaredLength > MAX_LOGIN_BODY_BYTES) return null;
  const reader = request.body?.getReader();
  if (!reader) return new URLSearchParams();
  const chunks = [];
  let totalLength = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalLength += value.byteLength;
    if (totalLength > MAX_LOGIN_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new URLSearchParams(new TextDecoder().decode(body));
}

async function loginRateAllowed(request, env) {
  if (!env.LOGIN_RATE_LIMITER || typeof env.LOGIN_RATE_LIMITER.limit !== 'function') return false;
  const source = request.headers.get('CF-Connecting-IP') || 'unknown-source';
  try {
    const result = await env.LOGIN_RATE_LIMITER.limit({ key: `login:${source}` });
    return result?.success === true;
  } catch {
    return false;
  }
}

async function handleLogin(request, env) {
  const url = new URL(request.url);
  if (request.method === 'GET') {
    if (await hasValidSession(request, env)) return redirect('/generator.html');
    return freshLoginPage({ next: requestedNext(url) });
  }
  if (request.method !== 'POST') return methodNotAllowed(['GET', 'POST']);
  if (!sameOrigin(request)) return freshLoginPage({ error: 'Permintaan login tidak valid.', status: 403 });
  if (!await loginRateAllowed(request, env)) {
    const response = freshLoginPage({ error: 'Terlalu banyak percobaan. Coba kembali sebentar lagi.', status: 429 });
    response.headers.set('Retry-After', '60');
    return response;
  }
  if (!validAuthSecrets(env)) {
    return freshLoginPage({ error: 'Layanan login sementara tidak tersedia.', status: 503 });
  }
  const form = await readLoginForm(request);
  if (!form) return freshLoginPage({ error: 'Permintaan login tidak valid.', status: 415 });
  if (!validLoginCsrf(request, form.get('csrf_token'))) {
    return freshLoginPage({ error: 'Permintaan login tidak valid.', status: 403 });
  }
  const username = form.get('username');
  const password = form.get('password');
  const next = requestedNext(url, form.get('next') || '');
  const validInput = typeof username === 'string'
    && typeof password === 'string'
    && username.length > 0
    && username.length <= MAX_USERNAME_LENGTH
    && password.length > 0
    && password.length <= MAX_PASSWORD_LENGTH;
  const valid = validInput && await verifyCredentials(username, password, env);
  if (!valid) return freshLoginPage({ error: 'Username atau password tidak valid.', status: 401, next });
  const token = await createSessionToken(env.SESSION_SIGNING_KEY);
  const response = redirect(next);
  response.headers.set('Set-Cookie', setSessionCookie(token));
  response.headers.append('Set-Cookie', clearLoginCsrfCookie());
  return response;
}

async function handleLogout(request) {
  if (request.method !== 'POST') return methodNotAllowed(['POST']);
  if (!sameOrigin(request)) return new Response(null, { status: 403, headers: authHeaders() });
  const response = redirect('/login');
  response.headers.set('Set-Cookie', clearSessionCookie());
  return response;
}

async function handleGenerator(request, env) {
  if (!['GET', 'HEAD'].includes(request.method)) return methodNotAllowed(['GET', 'HEAD']);
  if (!await hasValidSession(request, env)) return redirect('/login');
  const url = new URL(request.url);
  if (url.pathname !== '/generator.html') return redirect('/generator.html');
  // Cloudflare Static Assets canonicalizes `generator.html` to `/generator`.
  // Fetch the clean internal asset path so the protected route does not loop.
  const assetRequest = new Request(new URL('/generator', url), request);
  const assetResponse = await env.ASSETS.fetch(assetRequest);
  return new Response(assetResponse.body, {
    status: assetResponse.status,
    statusText: assetResponse.statusText,
    headers: withHeaders(assetResponse.headers, {
      ...authHeaders(GENERATOR_CSP),
      Vary: 'Cookie',
    }),
  });
}

async function instagramThumbnail(request, shortcode) {
  if (!['GET', 'HEAD'].includes(request.method)) {
    return new Response(null, { status: 405, headers: { Allow: 'GET, HEAD' } });
  }
  if (!INSTAGRAM_CODE.test(shortcode)) {
    return errorResponse('Invalid Instagram shortcode.', 400);
  }

  const upstream = await fetch(`https://www.instagram.com/p/${shortcode}/media/?size=l`, {
    headers: {
      Accept: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
      'User-Agent': 'Mozilla/5.0 (compatible; ORBContentFeed/1.0)',
    },
    cf: { cacheEverything: true, cacheTtl: 86400 },
  });
  const contentType = upstream.headers.get('Content-Type') || '';
  if (!upstream.ok || !contentType.toLowerCase().startsWith('image/')) {
    return errorResponse('Instagram thumbnail is unavailable.', upstream.status === 404 ? 404 : 502);
  }

  const headers = new Headers({
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'public, max-age=3600, s-maxage=86400, stale-while-revalidate=604800',
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
  });
  const etag = upstream.headers.get('ETag');
  if (etag) headers.set('ETag', etag);
  return new Response(request.method === 'HEAD' ? null : upstream.body, { status: 200, headers });
}

function strictHttpsUrl(value) {
  if (typeof value !== 'string' || !value || value.length > TIKTOK_URL_MAX_LENGTH) return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.port
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function isTikTokHost(hostname) {
  return TIKTOK_CANONICAL_HOSTS.has(hostname) || TIKTOK_SHORT_HOSTS.has(hostname);
}

export function parseTikTokUrl(value) {
  const parsed = strictHttpsUrl(value);
  if (!parsed) return null;
  const hostname = parsed.hostname.toLowerCase();
  if (TIKTOK_CANONICAL_HOSTS.has(hostname)) {
    const match = parsed.pathname.match(/^\/@([A-Za-z0-9._-]{2,30})\/video\/([0-9]{10,25})\/?$/u);
    if (!match) return null;
    parsed.hash = '';
    return { kind: 'canonical', url: parsed.href, videoId: match[2] };
  }
  if (TIKTOK_SHORT_HOSTS.has(hostname) && /^\/[A-Za-z0-9_-]{4,128}\/?$/u.test(parsed.pathname)) {
    parsed.hash = '';
    return { kind: 'short', url: parsed.href };
  }
  return null;
}

function safeTikTokRedirect(value, base) {
  if (typeof value !== 'string') return null;
  try {
    const parsed = new URL(value, base);
    if (parsed.href.length > TIKTOK_URL_MAX_LENGTH
      || parsed.protocol !== 'https:'
      || parsed.username
      || parsed.password
      || parsed.port
      || !isTikTokHost(parsed.hostname.toLowerCase())) return null;
    parsed.hash = '';
    return parsed;
  } catch {
    return null;
  }
}

function isRedirect(response) {
  return [301, 302, 303, 307, 308].includes(response.status);
}

async function discardBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // The body is best-effort cleanup only.
  }
}

async function resolveTikTokUrl(info) {
  if (info.kind === 'canonical') return info.url;
  let current = info.url;
  for (let redirects = 0; redirects < TIKTOK_REDIRECT_LIMIT; redirects += 1) {
    const response = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ORBContentFeed/1.0)' },
    });
    const location = response.headers.get('Location');
    await discardBody(response);
    if (!isRedirect(response) || !location) throw new Error('TikTok short link did not resolve');
    const destination = safeTikTokRedirect(location, current);
    if (!destination) throw new Error('Unsafe TikTok redirect');
    const resolved = parseTikTokUrl(destination.href);
    if (resolved?.kind === 'canonical') return resolved.url;
    current = destination.href;
  }
  throw new Error('Too many TikTok redirects');
}

function safeTikTokThumbnailUrl(value, base) {
  if (typeof value !== 'string') return null;
  try {
    const parsed = new URL(value, base);
    const hostname = parsed.hostname.toLowerCase();
    const allowedHost = TIKTOK_THUMBNAIL_HOST_ROOTS.some(
      (root) => hostname === root || hostname.endsWith(`.${root}`),
    );
    if (parsed.href.length > TIKTOK_URL_MAX_LENGTH
      || parsed.protocol !== 'https:'
      || parsed.username
      || parsed.password
      || parsed.port
      || !allowedHost) return null;
    parsed.hash = '';
    return parsed;
  } catch {
    return null;
  }
}

async function fetchTikTokImage(value, method) {
  let current = safeTikTokThumbnailUrl(value);
  if (!current) throw new Error('Unsafe TikTok thumbnail URL');
  for (let redirects = 0; redirects <= TIKTOK_REDIRECT_LIMIT; redirects += 1) {
    const response = await fetch(current.href, {
      method,
      redirect: 'manual',
      headers: {
        Accept: 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
        'User-Agent': 'Mozilla/5.0 (compatible; ORBContentFeed/1.0)',
      },
      cf: { cacheEverything: true, cacheTtl: 86400 },
    });
    if (!isRedirect(response)) return response;
    const location = response.headers.get('Location');
    await discardBody(response);
    if (redirects === TIKTOK_REDIRECT_LIMIT || !location) throw new Error('Too many TikTok image redirects');
    current = safeTikTokThumbnailUrl(location, current.href);
    if (!current) throw new Error('Unsafe TikTok image redirect');
  }
  throw new Error('TikTok thumbnail is unavailable');
}

async function tiktokThumbnail(request, url) {
  if (!['GET', 'HEAD'].includes(request.method)) {
    return publicApiError(request, 'Method not allowed.', 405, ['GET', 'HEAD']);
  }
  if (typeof url !== 'string') return publicApiError(request, 'TikTok URL is required.', 400);
  if (url.length > TIKTOK_URL_MAX_LENGTH) return publicApiError(request, 'TikTok URL is too long.', 414);
  const info = parseTikTokUrl(url);
  if (!info) return publicApiError(request, 'Invalid TikTok URL.', 400);

  let stage = 'resolve-url';
  try {
    const canonicalUrl = await resolveTikTokUrl(info);
    stage = 'fetch-oembed';
    const oembedUrl = new URL(TIKTOK_OEMBED_ENDPOINT);
    oembedUrl.searchParams.set('url', canonicalUrl);
    const metadataResponse = await fetch(oembedUrl.href, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; ORBContentFeed/1.0)',
      },
      cf: { cacheEverything: true, cacheTtl: 3600 },
    });
    const metadataType = metadataResponse.headers.get('Content-Type') || '';
    if (!metadataResponse.ok || !/(?:application\/json|\+json)(?:;|$)/iu.test(metadataType)) {
      await discardBody(metadataResponse);
      return publicApiError(request, 'TikTok metadata is unavailable.', 502);
    }
    let metadata;
    try {
      metadata = await metadataResponse.json();
    } catch {
      return publicApiError(request, 'TikTok metadata is unavailable.', 502);
    }
    if (metadata?.type !== 'video' || metadata.provider_name !== 'TikTok') {
      return publicApiError(request, 'TikTok metadata is unavailable.', 502);
    }
    stage = 'validate-thumbnail-url';
    const thumbnailUrl = safeTikTokThumbnailUrl(metadata?.thumbnail_url);
    if (!thumbnailUrl) return publicApiError(request, 'TikTok thumbnail is unavailable.', 502);
    stage = 'fetch-thumbnail';
    const imageResponse = await fetchTikTokImage(thumbnailUrl.href, request.method);
    const contentType = imageResponse.headers.get('Content-Type') || '';
    if (!imageResponse.ok || !contentType.toLowerCase().startsWith('image/')) {
      await discardBody(imageResponse);
      return publicApiError(request, 'TikTok thumbnail is unavailable.', 502);
    }

    const headers = new Headers({
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600, s-maxage=86400, stale-while-revalidate=604800',
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
    });
    const etag = imageResponse.headers.get('ETag');
    if (etag) headers.set('ETag', etag);
    return new Response(request.method === 'HEAD' ? null : imageResponse.body, { status: 200, headers });
  } catch (error) {
    const reason = String(error?.message || '').replace(/https?:\/\/\S+/gu, '<url>');
    console.warn('TikTok thumbnail request failed.', { stage, error: error?.name || 'Error', reason });
    return publicApiError(request, 'TikTok thumbnail is unavailable.', 502);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/login') return handleLogin(request, env);
    if (url.pathname === '/api/logout') return handleLogout(request);
    if (GENERATOR_PATHS.has(url.pathname)) return handleGenerator(request, env);
    const match = url.pathname.match(/^\/api\/instagram-thumbnail\/([^/]+)$/u);
    if (match) return instagramThumbnail(request, match[1]);
    if (url.pathname === '/api/tiktok-thumbnail') {
      const values = url.searchParams.getAll('url');
      const onlyUrlParameter = [...url.searchParams.keys()].every((name) => name === 'url');
      const value = values.length === 1 && onlyUrlParameter ? values[0] : null;
      return tiktokThumbnail(request, value);
    }
    return env.ASSETS.fetch(request);
  },
};

export const authConstants = {
  PBKDF2_ITERATIONS,
  SESSION_LIFETIME_SECONDS,
  SESSION_COOKIE,
  LOGIN_CSRF_COOKIE,
};
