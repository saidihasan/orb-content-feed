import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { verifyProductionLogin } from './production-login-check.mjs';

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
        if (character === '\u007f' || character === '\b') value = value.slice(0, -1);
        else if (character >= ' ') value += character;
      }
      return finish();
    }

    stdin.on('data', onData);
  });
}

async function main() {
  const usernamePrompt = createInterface({ input: stdin, output: stdout });
  const username = (await usernamePrompt.question('Username admin production: ')).trim();
  usernamePrompt.close();
  if (!username || username.length > 128) throw new Error('Username tidak valid.');

  const password = await readHidden('Password admin production: ');
  if (!password || password.length > 1024) throw new Error('Password tidak valid.');

  stdout.write('Memeriksa login langsung ke Cloudflare...\n');
  const result = await verifyProductionLogin(username, password);
  if (result === 'success') {
    stdout.write('VALID: credential production diterima dan cookie sesi 8 jam dibuat.\n');
    return;
  }
  if (result === 'rate-limited') {
    throw new Error('RATE_LIMITED: tunggu minimal 60 detik tanpa mencoba login, lalu jalankan lagi.');
  }
  if (result === 'unavailable') {
    throw new Error('UNAVAILABLE: deployment belum tersebar atau secrets belum tersedia; tunggu 60 detik lalu coba lagi.');
  }
  throw new Error('INVALID: credential yang dimasukkan tidak cocok dengan secret production aktif.');
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
