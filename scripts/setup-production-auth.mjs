import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { verifyProductionLogin } from './production-login-check.mjs';

const ITERATIONS = 100_000;

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function readHidden(prompt) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    throw new Error('Jalankan perintah ini langsung di terminal interaktif.');
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

function deployWithSecretsOnce(payload) {
  if (process.platform === 'win32') {
    throw new Error('Deployment melalui /dev/stdin memerlukan macOS atau Linux.');
  }
  const child = spawn('npx', ['--yes', 'wrangler', 'deploy', '--secrets-file', '/dev/stdin'], {
    stdio: ['pipe', 'inherit', 'inherit'],
  });

  child.stdin.on('error', () => {});
  child.stdin.end(payload);

  return new Promise((resolve, reject) => {
    child.once('error', () => reject(new Error('Wrangler tidak dapat dijalankan.')));
    child.once('exit', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`Deployment atomik gagal${signal ? ` (${signal})` : ''}.`));
    });
  });
}

async function deployWithSecrets(payload) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      await deployWithSecretsOnce(payload);
      return;
    } catch (error) {
      lastError = error;
      if (attempt === 3) break;
      stdout.write(`Koneksi gagal; mencoba ulang (${attempt + 1}/3)...\n`);
      await delay(attempt * 2_000);
    }
  }
  throw lastError;
}

async function main() {
  const usernamePrompt = createInterface({ input: stdin, output: stdout });
  const username = (await usernamePrompt.question('Username admin production baru: ')).trim();
  usernamePrompt.close();
  if (!username || username.length > 128) throw new Error('Username harus berisi 1–128 karakter.');

  const password = await readHidden('Password admin production baru: ');
  if (password.length < 20) throw new Error('Gunakan passphrase unik minimal 20 karakter.');
  if (password.length > 1024) throw new Error('Password terlalu panjang.');
  const confirmation = await readHidden('Ulangi password: ');
  if (password !== confirmation) throw new Error('Konfirmasi password tidak cocok.');

  const approvalPrompt = createInterface({ input: stdin, output: stdout });
  const approval = (await approvalPrompt.question(
    'Ketik ROTATE_DEPLOY untuk mengganti secret dan deploy Worker production secara atomik: ',
  )).trim();
  approvalPrompt.close();
  if (approval !== 'ROTATE_DEPLOY') throw new Error('Dibatalkan; production tidak diubah.');

  const salt = randomBytes(16);
  const passwordHash = pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
  const sessionKey = randomBytes(32);
  const payload = JSON.stringify({
    ADMIN_USERNAME: username,
    ADMIN_PASSWORD_SALT: salt.toString('base64url'),
    ADMIN_PASSWORD_HASH: passwordHash.toString('base64url'),
    SESSION_SIGNING_KEY: sessionKey.toString('base64url'),
  });

  try {
    stdout.write('Men-deploy Worker dan secret production secara atomik melalui stdin...\n');
    await deployWithSecrets(payload);
    stdout.write('Deployment selesai. Memverifikasi credential yang sama langsung ke production...\n');
    await delay(10_000);
    let result;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      result = await verifyProductionLogin(username, password);
      if (!['invalid', 'unavailable'].includes(result) || attempt === 3) break;
      await delay(5_000);
    }
    if (result === 'rate-limited') {
      throw new Error(
        'Deployment selesai, tetapi verifikasi terkena rate limit. Tunggu 60 detik lalu jalankan npm run auth:verify:production.',
      );
    }
    if (result === 'unavailable') {
      throw new Error(
        'Deployment selesai, tetapi belum tersebar ke edge ini. Tunggu 60 detik lalu jalankan npm run auth:verify:production.',
      );
    }
    if (result !== 'success') {
      throw new Error('Deployment selesai, tetapi Worker menolak credential yang sama.');
    }
    stdout.write('VALID: deployment atomik berhasil dan login production menerima credential baru.\n');
  } finally {
    salt.fill(0);
    passwordHash.fill(0);
    sessionKey.fill(0);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
