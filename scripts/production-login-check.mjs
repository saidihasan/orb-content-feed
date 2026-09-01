const PRODUCTION_ORIGIN = 'https://orb-content-feed.saidihasan.workers.dev';

export async function verifyProductionLogin(username, password) {
  const loginPage = await fetch(`${PRODUCTION_ORIGIN}/login`, {
    headers: { 'Cache-Control': 'no-cache' },
    redirect: 'manual',
  });
  if (loginPage.status !== 200) throw new Error(`Halaman login merespons HTTP ${loginPage.status}.`);

  const setCookie = loginPage.headers.get('set-cookie') || '';
  const csrfCookie = setCookie.match(/__Host-orb_login_csrf=([^;]+)/u)?.[1];
  const html = await loginPage.text();
  const csrfForm = html.match(/name="csrf_token" value="([^"]+)"/u)?.[1];
  if (!csrfCookie || !csrfForm || csrfCookie !== csrfForm) {
    throw new Error('Token CSRF production tidak dapat diverifikasi.');
  }

  const body = new URLSearchParams({
    csrf_token: csrfForm,
    next: '/generator.html',
    username,
    password,
  });
  const response = await fetch(`${PRODUCTION_ORIGIN}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: `__Host-orb_login_csrf=${csrfCookie}`,
      Origin: PRODUCTION_ORIGIN,
    },
    body,
    redirect: 'manual',
  });

  if (response.status === 303) {
    const sessionCookie = response.headers.get('set-cookie') || '';
    if (!sessionCookie.includes('__Host-orb_admin_session=') || !sessionCookie.includes('Max-Age=28800')) {
      throw new Error('Login diterima, tetapi session cookie production tidak sesuai.');
    }
    return 'success';
  }
  if (response.status === 401) return 'invalid';
  if (response.status === 429) return 'rate-limited';
  if (response.status === 503) return 'unavailable';
  throw new Error(`Endpoint login merespons HTTP ${response.status}.`);
}
