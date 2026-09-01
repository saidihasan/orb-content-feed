import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

const ITERATIONS = 100_000;

function readHidden(prompt) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    const fallback = createInterface({ input: stdin, output: stdout });
    return fallback.question(`${prompt} (input mungkin terlihat): `).finally(() => fallback.close());
  }

  return new Promise((resolve, reject) => {
    let value = '';
    let rawValue = '';
    stdout.write(prompt);
    stdin.setEncoding('utf8');
    stdin.setRawMode(true);
    stdin.resume();

    function finish(error) {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write('\n');
      if (error) reject(error);
      else resolve(value);
    }

    function onData(chunk) {
      rawValue += chunk;
      if (rawValue.includes('\u0003')) return finish(new Error('Dibatalkan.'));

      const enterIndex = rawValue.search(/[\r\n]/u);
      if (enterIndex === -1) return;

      const input = rawValue
        .slice(0, enterIndex)
        .replaceAll('\u001b[200~', '')
        .replaceAll('\u001b[201~', '');
      for (const character of input) {
        if (character === '\u007f' || character === '\b') {
          value = value.slice(0, -1);
        } else if (character >= ' ') {
          value += character;
        }
      }
      return finish();
    }

    stdin.on('data', onData);
  });
}

async function main() {
  const usernamePrompt = createInterface({ input: stdin, output: stdout });
  const username = (await usernamePrompt.question('Username admin: ')).trim();
  usernamePrompt.close();
  if (!username || username.length > 128) throw new Error('Username harus berisi 1–128 karakter.');

  const password = await readHidden('Password admin: ');
  if (password.length < 20) throw new Error('Gunakan passphrase unik minimal 20 karakter.');
  if (password.length > 1024) throw new Error('Password terlalu panjang.');
  const confirmation = await readHidden('Ulangi password: ');
  if (password !== confirmation) throw new Error('Konfirmasi password tidak cocok.');

  const salt = randomBytes(16);
  const passwordHash = pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
  const sessionKey = randomBytes(32);
  const devVars = [
    `ADMIN_USERNAME=${JSON.stringify(username)}`,
    `ADMIN_PASSWORD_SALT=${JSON.stringify(salt.toString('base64url'))}`,
    `ADMIN_PASSWORD_HASH=${JSON.stringify(passwordHash.toString('base64url'))}`,
    `SESSION_SIGNING_KEY=${JSON.stringify(sessionKey.toString('base64url'))}`,
    '',
  ].join('\n');

  writeFileSync('.dev.vars', devVars, { encoding: 'utf8', flag: 'wx', mode: 0o600 });

  stdout.write(`
Credential lokal berhasil disimpan ke .dev.vars dengan permission terbatas.
Password plaintext tidak disimpan dan nilai secrets tidak dicetak.

Untuk konfigurasi production nanti, masukkan setiap nilai .dev.vars melalui prompt interaktif berikut; jangan menaruh nilainya di command line:

npx wrangler secret put ADMIN_USERNAME
npx wrangler secret put ADMIN_PASSWORD_SALT
npx wrangler secret put ADMIN_PASSWORD_HASH
npx wrangler secret put SESSION_SIGNING_KEY

.dev.vars sudah diabaikan Git. Jangan commit atau membagikan isinya.
`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
