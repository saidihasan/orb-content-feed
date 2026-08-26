# ORB Static Content Feed

Feed konten statis ringan untuk **Biro Organisasi Setda Provinsi Banten**. Admin mengelola daftar Instagram dan YouTube melalui halaman visual, lalu mengunduh `latest.json` tanpa menulis JSON secara manual. Situs utama mengambil file tersebut dengan `fetch()` dan menampilkan maksimal tiga konten berdasarkan `published_at` terbaru.

Proyek ini hanya menggunakan HTML, CSS, dan JavaScript vanilla. Tidak ada npm, build process, backend, database, API Instagram, atau token akses.

## Struktur

- `index.html` — halaman diagnosis publik dan pratinjau tiga konten terbaru.
- `generator.html` — editor admin, penyimpanan browser, impor, dan ekspor JSON.
- `latest.json` — data feed publik; boleh menyimpan seluruh riwayat konten.
- `website-integration.html` — demonstrasi dan blok integrasi siap salin-tempel.
- `thumbnails/` — aset thumbnail lokal untuk Instagram.
- `_headers` — CORS dan cache headers untuk Cloudflare Pages.
- `.gitignore` — file lokal yang tidak boleh masuk repository.

## Menjalankan secara lokal

Jalankan server statis dari root proyek:

```bash
python3 -m http.server 8000
```

Kemudian buka:

- `http://localhost:8000/` untuk diagnosis publik.
- `http://localhost:8000/generator.html` untuk generator admin.
- `http://localhost:8000/website-integration.html` untuk contoh integrasi.

Generator juga dapat dibuka langsung sebagai file, tetapi server lokal disarankan agar perilakunya sama dengan deployment.

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

1. Buka `generator.html`.
2. Impor `latest.json` yang sedang digunakan.
3. Tambah, edit, hapus, duplikat, atau atur posisi konten.
4. Tambahkan thumbnail ke folder `thumbnails/` jika diperlukan.
5. Unduh `latest.json` dari generator.
6. Ganti `latest.json` di repository dan tambahkan thumbnail baru.
7. Commit dan push perubahan.
8. Cloudflare Pages melakukan deployment ulang otomatis.

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
git add latest.json thumbnails/
git commit -m "Update content feed"
git push
```

Jika repository sudah mempunyai remote `origin`, pertahankan dan gunakan remote tersebut. Jangan menyimpan password, Personal Access Token, API key, cookie, atau credential lain di file proyek maupun commit.

## Cloudflare Pages

Di Cloudflare Dashboard pilih **Workers & Pages → Create application → Pages → Connect to Git → GitHub → orb-content-feed**.

Gunakan konfigurasi:

- Production branch: `main`
- Framework preset: `None`
- Build command: `exit 0`
- Build output directory: `.`

Sesudah Cloudflare memberi domain, buka `website-integration.html` dan ganti:

```js
const contentFeedUrl =
  'https://CHANGE-ME.pages.dev/latest.json';
```

dengan URL deployment yang sebenarnya, misalnya `https://domain-yang-diberikan.pages.dev/latest.json`. Jangan menebak domain sebelum Cloudflare membuatnya. Tombol **Salin kode integrasi** menyediakan blok yang siap ditempel ke website utama.

## Troubleshooting

- **Feed tidak dapat dimuat:** pastikan halaman dibuka melalui server HTTP, `latest.json` ada di root, JSON valid, dan deployment terbaru sudah selesai.
- **Thumbnail tidak muncul:** periksa URL HTTPS atau nama/path file di `thumbnails/`, termasuk kapitalisasi.
- **YouTube tidak terdeteksi:** gunakan format `youtube.com/watch?v=…`, `youtu.be/…`, atau `youtube.com/shorts/…`.
- **Impor ditolak:** pesan generator menunjukkan item dan field yang tidak valid; data aktif tidak diganti.
- **Salin JSON ditolak browser:** gunakan tombol **Unduh latest.json**.
- **Website utama masih menampilkan fallback:** ganti `contentFeedUrl` dengan domain Cloudflare Pages yang benar dan periksa CORS `_headers`.

Feed ini bersifat publik. Jangan pernah memasukkan credential atau data rahasia ke `latest.json`, source code, thumbnail metadata, maupun riwayat Git.
