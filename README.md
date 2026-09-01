# ORB Static Content Feed

Feed konten statis ringan untuk **Biro Organisasi Setda Provinsi Banten**. Admin mengelola daftar Instagram dan YouTube melalui halaman visual yang dilindungi login, lalu mengunduh `latest.json` tanpa menulis JSON secara manual. Situs utama mengambil file tersebut dengan `fetch()` dan menampilkan maksimal tiga konten berdasarkan `published_at` terbaru.

Antarmuka menggunakan HTML, CSS, dan JavaScript vanilla. Cloudflare Worker menangani autentikasi admin serta memproksikan thumbnail publik Instagram agar dapat ditampilkan lintas domain. Tidak ada database, API token, atau credential Instagram.

## Struktur

- `public/index.html` — halaman diagnosis publik dan pratinjau tiga konten terbaru.
- `public/generator.html` — editor admin, penyimpanan browser, impor, dan ekspor JSON.
- `public/feed-loader.js` — pemuat dan validasi feed production tanpa mengubah data editor saat terjadi kegagalan.
- `public/latest.json` — data feed publik; boleh menyimpan seluruh riwayat konten.
- `public/website-integration.html` — demonstrasi dan blok integrasi siap salin-tempel.
- `worker.js` — autentikasi admin, sesi, dan proxy terbatas untuk thumbnail publik Instagram.
- `scripts/generate-auth-secrets.mjs` — generator lokal untuk salt, hash password, dan kunci sesi.
- `test/worker.test.mjs` — pengujian rute publik dan autentikasi.
- `public/thumbnails/` — aset thumbnail lokal untuk Instagram.
- `public/_headers` — CORS dan cache headers untuk aset Cloudflare Worker.
- `.gitignore` — file lokal yang tidak boleh masuk repository.

## Menjalankan secara lokal

Siapkan credential lokal terlebih dahulu:

```bash
npm run auth:setup
```

Script meminta username dan passphrase unik minimal 20 karakter. Password disembunyikan jika terminal mendukungnya. Script langsung membuat `.dev.vars` dengan permission terbatas dan tidak menyimpan password plaintext:

```dotenv
ADMIN_USERNAME=<nilai-yang-dihasilkan>
ADMIN_PASSWORD_SALT=<nilai-yang-dihasilkan>
ADMIN_PASSWORD_HASH=<nilai-yang-dihasilkan>
SESSION_SIGNING_KEY=<nilai-yang-dihasilkan>
```

Nilai di atas hanya menunjukkan struktur file; nilai sebenarnya tidak dicetak oleh script. `.dev.vars` dan `.env*` diabaikan Git. Jangan pernah commit atau membagikan file secrets.

Jalankan Cloudflare Worker lokal dari root proyek:

```bash
npx wrangler dev
```

Kemudian buka:

- `http://localhost:8787/` untuk diagnosis publik.
- `http://localhost:8787/generator` untuk generator admin.
- `http://localhost:8787/website-integration` untuk contoh integrasi.

Gunakan server Worker lokal agar proxy thumbnail Instagram tersedia dan perilakunya sama dengan deployment.

## Autentikasi admin

- `/generator`, `/generator/`, dan `/generator.html` hanya tersedia setelah login.
- Username dan hash password hanya dibaca dari Cloudflare Secrets di sisi Worker.
- Password diverifikasi menggunakan PBKDF2-HMAC-SHA256 dengan 100.000 iterasi, yaitu batas
  maksimum runtime Cloudflare Workers. Gunakan passphrase production unik minimal 20 karakter.
- Session cookie ditandatangani HMAC-SHA256, bersifat `HttpOnly`, `Secure`, dan `SameSite=Strict`.
- Sesi berakhir tepat setelah 8 jam dan tidak diperpanjang oleh aktivitas.
- Login dibatasi sekitar lima percobaan per menit per sumber oleh Rate Limiting binding Cloudflare.
- Form login dilindungi token CSRF cookie+form berumur 10 menit; opaque origin hanya diterima bila browser menandainya `same-origin`.
- `latest.json`, halaman diagnosis, thumbnail, dan API thumbnail Instagram tetap publik.

Jalankan pengujian keamanan dan regresi dengan:

```bash
npm test
```

## Format `latest.json`

```json
{
  "feed_name": "Biro Organisasi Setda Provinsi Banten",
  "updated_at": "2026-08-26T10:00:00+07:00",
  "items": [
    {
      "id": "contoh-konten",
      "platform": "instagram",
      "type": "post",
      "title": "Contoh Konten",
      "url": "https://www.instagram.com/p/example/",
      "thumbnail": "thumbnails/contoh.webp",
      "thumbnail_fit": "cover",
      "published_at": "2026-08-26T09:00:00+07:00"
    }
  ]
}
```

Enum yang didukung:

- `platform`: `instagram`, `youtube`
- `type`: `post`, `reel`, `video`, `short`
- `thumbnail_fit`: `cover`, `contain`

Gunakan ID unik dan stabil serta tanggal ISO-8601 dengan offset `+07:00`. Urutan array tidak menentukan urutan tampilan; aplikasi mengurutkan `published_at` terbaru.

## Workflow admin harian

1. Buka `generator.html` dan login sebagai admin.
2. Klik **Muat Feed Aktif** untuk mengambil data production, atau gunakan **Impor JSON** untuk file lokal.
3. Tambah, edit, hapus, duplikat, atau atur posisi konten.
4. Thumbnail Instagram dan YouTube terisi otomatis. Jika thumbnail Instagram tidak tersedia, masukkan URL lain atau tambahkan gambar ke folder `thumbnails/`.
5. Unduh `latest.json` dari generator.
6. Ganti `latest.json` di repository dan tambahkan thumbnail baru.
7. Commit dan push perubahan.
8. Cloudflare Workers melakukan deployment ulang melalui workflow deployment yang digunakan.

Data kerja tersimpan di `localStorage` pada browser. Tetap unduh JSON sebagai salinan utama sebelum berpindah perangkat atau membersihkan data browser.

## GitHub

Cara utama dengan GitHub CLI:

```bash
gh auth login
gh repo create orb-content-feed \
  --public \
  --source=. \
  --remote=origin \
  --push
```

Fallback manual:

```bash
git init
git branch -M main
git add .
git commit -m "Initial ORB static content feed"
git remote add origin https://github.com/USERNAME/orb-content-feed.git
git push -u origin main
```

Pembaruan rutin:

```bash
git add public/latest.json public/thumbnails/
git commit -m "Update content feed"
git push
```

Jika repository sudah mempunyai remote `origin`, pertahankan dan gunakan remote tersebut. Jangan menyimpan password, Personal Access Token, API key, cookie, atau credential lain di file proyek maupun commit.

## Cloudflare Workers

Sebelum deployment pertama, buat nilai aman secara lokal dengan `npm run auth:setup`, lalu masukkan masing-masing nilai melalui prompt interaktif Wrangler:

```bash
npx wrangler secret put ADMIN_USERNAME
npx wrangler secret put ADMIN_PASSWORD_SALT
npx wrangler secret put ADMIN_PASSWORD_HASH
npx wrangler secret put SESSION_SIGNING_KEY
```

Jika pasangan salt/hash production salah atau credential perlu dirotasi, gunakan:

```sh
npm run auth:setup:production
```

Perintah ini meminta credential baru langsung di terminal, membuat keempat nilai yang saling
sesuai, lalu memublikasikan Worker, aset, dan secrets secara atomik melalui
`wrangler deploy --secrets-file /dev/stdin`. Nilai secret tidak ditulis ke file, command line,
atau output terminal. Menjalankannya akan mengakhiri semua sesi admin production yang sedang aktif.

Jangan menambahkan nilai secret langsung ke command line, `wrangler.jsonc`, source code, atau riwayat Git. Memasukkan secret melalui prompt interaktif mencegah nilainya tersimpan dalam shell history.

Publikasikan aset statis dan proxy thumbnail sebagai satu Worker:

```bash
npx wrangler deploy
```

Feed production yang digunakan generator dan integrasi website adalah:

```js
const contentFeedUrl =
  'https://orb-content-feed.saidihasan.workers.dev/latest.json';
```

`public/website-integration.html` sudah memuat URL tersebut. Tombol **Salin kode integrasi** menyediakan blok yang siap ditempel ke website utama. Generator menampilkan URL aktif serta tautan langsung ke feed publik dan halaman diagnosis.

## Troubleshooting

- **Feed tidak dapat dimuat:** pastikan halaman dibuka melalui server HTTP, `latest.json` ada di root, JSON valid, dan deployment terbaru sudah selesai.
- **Thumbnail Instagram tidak muncul:** pastikan posting publik dan URL memakai format `instagram.com/p/…` atau `instagram.com/reel/…`. Endpoint publik Instagram dapat berubah; gunakan URL thumbnail manual atau file di `thumbnails/` sebagai fallback.
- **Thumbnail lain tidak muncul:** periksa URL HTTPS atau nama/path file di `thumbnails/`, termasuk kapitalisasi.
- **YouTube tidak terdeteksi:** gunakan format `youtube.com/watch?v=…`, `youtu.be/…`, atau `youtube.com/shorts/…`.
- **Login lokal tidak tersedia:** pastikan keempat nilai autentikasi ada di `.dev.vars`, lalu mulai ulang `wrangler dev`.
- **Terlalu banyak percobaan login:** tunggu sekurangnya 60 detik sebelum mencoba kembali.
- **Sesi berakhir:** login kembali; sesi admin memang berakhir tetap setelah delapan jam.
- **Impor ditolak:** pesan generator menunjukkan item dan field yang tidak valid; data aktif tidak diganti.
- **Salin JSON ditolak browser:** gunakan tombol **Unduh latest.json**.
- **Website utama masih menampilkan fallback:** periksa akses ke `https://orb-content-feed.saidihasan.workers.dev/latest.json` dan header CORS di `public/_headers`.

Feed ini bersifat publik. Jangan pernah memasukkan credential atau data rahasia ke `latest.json`, source code, thumbnail metadata, maupun riwayat Git.
