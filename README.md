# SSGhost666

Pemindai keamanan web berbasis CLI, ditulis dalam Go. Fokusnya adalah
**pengumpulan bukti** (evidence gathering) terhadap aplikasi web yang Anda
miliki atau telah mendapat izin eksplisit untuk diuji: menemukan
halaman/endpoint, meng-crawl rute yang dimuat JavaScript, mengimpor
definisi API, lalu menjalankan pemeriksaan terarah untuk SQL injection,
XSS, command injection, SSRF, masalah autentikasi, dan beberapa
pemeriksaan pasif — dengan setiap temuan membawa bukti request/response
mentah.

> **Hanya pindai aplikasi yang Anda miliki atau yang secara eksplisit
> mengizinkan Anda mengujinya.** Alat ini mencetak pengingat ini setiap
> kali dijalankan. Anda bertanggung jawab penuh atas penggunaannya.

## Fitur

- **Crawling statis**: parsing HTML (`<a>`, `<form>`, `<script src>`), level demi level sampai `-depth`.
- **Ekstraksi endpoint dari JS**: setiap file `.js` yang ditemukan dipindai dengan heuristik ala LinkFinder untuk menemukan path/endpoint yang disebut di dalamnya — tanpa perlu menjalankan JavaScript.
- **Crawling dinamis via headless Chrome** (`-js-render`): merender halaman sungguhan dan menangkap setiap panggilan `fetch`/XHR yang dilakukan JavaScript saat halaman berjalan — ini yang menemukan rute yang *hanya* muncul setelah bundel JS dieksekusi (umum pada SPA).
- **Discovery endpoint tersembunyi**: brute-force wordlist (bawaan kecil, atau `-wordlist` milik Anda sendiri seperti SecLists), plus parsing `robots.txt` dan `sitemap.xml`. Dilengkapi **kalibrasi soft-404 otomatis** (seperti ffuf/wfuzz) — memprobe path acak dulu untuk belajar bagaimana bentuk respons "tidak ada apa-apa di sini" pada server target, supaya halaman catch-all tidak membanjiri hasil dengan positif palsu.
- **Impor OpenAPI 3 / Swagger 2** (`-openapi`, JSON maupun YAML, file lokal atau URL): setiap operasi beserta parameternya otomatis menjadi target pindai, termasuk resolusi penuh `$ref` (parameter, request body, maupun skema yang saling menunjuk, lokal dalam satu dokumen) dan `allOf` (menggabungkan properti dari beberapa skema dasar + ekstensi — pola "base schema + per-endpoint fields" yang umum di dunia nyata).
- **Sesi terautentikasi**: `-cookie`, `-bearer`, atau `-header` kustom (bisa diulang).
- **Proxy**: `-proxy http://127.0.0.1:8080` untuk merutekan semua trafik lewat Burp/ZAP/mitmproxy agar bisa dipantau langsung.
- **Pemeriksaan aktif SQL injection**, tiga teknik berjenjang (tercepat dicoba dulu, teknik berikutnya hanya jalan jika yang sebelumnya nihil):
  1. *Error-based* — payload pemecah sintaks, cari signature error database di respons.
  2. *Boolean-based blind* — kirim pasangan payload true/false, bandingkan respons; perlu **dua pasangan independen** yang konsisten sebelum dilaporkan, supaya halaman yang sekadar sedikit berubah antar-request tidak dikira rentan.
  3. *Time-based blind* — payload yang membuat database "tidur", dengan **konfirmasi ganda** (request diulang) sebelum dilaporkan.
- **Reflected XSS dengan konfirmasi eksekusi nyata**: deteksi awal lewat refleksi payload di respons HTTP (cepat, tanpa browser). Jika `-js-render` diaktifkan dan hit-nya berupa request GET lewat parameter query/path, SSGhost666 melangkah lebih jauh — membuka tab headless Chrome sungguhan, navigasi ke URL persis yang memicu refleksi, lalu memeriksa apakah skrip yang disuntik **benar-benar tereksekusi** (bukan cuma cocok teks). Temuan yang terkonfirmasi lewat eksekusi browser naik ke severity Critical dan ditandai jelas "(executed in browser)"; yang cuma refleksi tanpa bisa dikonfirmasi tetap dilaporkan tapi ditandai "(unconfirmed — reflection only)". Ini juga otomatis menyaring positif-palsu sebaliknya: payload yang "terlihat" reflected di teks mentah tapi ternyata jatuh di konteks mati (dalam komentar HTML, misalnya) akan ketahuan tidak benar-benar jalan.
- **OS command injection** (time-based blind, konfirmasi ganda) dan **SSRF** (deteksi in-band ke metadata cloud — dengan penyaringan agar endpoint yang sekadar meng-echo input tidak salah terdeteksi — plus dukungan callback OOB seperti Burp Collaborator/interact.sh).
- **Pemeriksaan autentikasi**: kesalahan konfigurasi CORS, indikasi broken access control (dibandingkan dengan & tanpa kredensial, disaring agar tidak berisik di halaman publik biasa), flag keamanan cookie, decode JWT (mendeteksi `alg: none`, klaim `exp` yang hilang).
- **Pemeriksaan pasif**: header keamanan yang hilang, kebocoran versi lewat header `Server`/`X-Powered-By`, stack trace/error verbose, directory listing, mixed content, **dan pustaka JavaScript dengan versi yang diketahui rentan** (jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, Handlebars, Underscore.js, AngularJS — dicocokkan dari banner versi di file JS atau nama filenya, terhadap tabel CVE publik yang sudah diverifikasi, masing-masing dengan referensi CVE dan saran upgrade).
- **Output terminal berwarna**, langsung terbaca, dengan temuan dicetak live saat ditemukan.
- **Laporan HTML** (`-out report.html`) mandiri (tanpa dependensi eksternal) berisi bukti request/response lengkap per temuan, dengan auto-escaping yang benar (payload yang direfleksikan tidak akan "hidup" sebagai HTML di laporan) dan redaksi otomatis header `Authorization`/`Cookie` (nonaktifkan dengan `-no-redact`).
- **Rate limiting & concurrency yang sopan secara default** (`-rate`, `-concurrency`, `-max-requests`) — setiap request HTTP sungguhan melewati limiter yang sama, bukan hanya longgar per "tugas".

## Build

Butuh Go 1.23 atau lebih baru.

```bash
cd ssghost666
go build -o ssghost666 .
```

`go.mod` sudah menyertakan versi dependensi yang sudah diverifikasi bekerja
(lihat komentar di dalamnya). Jika build pertama gagal karena masalah
checksum/proxy di jaringan Anda, coba:

```bash
GOPROXY=direct GOSUMDB=off go build -o ssghost666 .
```

atau jalankan `go mod tidy` sekali (butuh akses internet normal) untuk
menyegarkan `go.sum` sesuai lingkungan Anda.

## Pemakaian

```bash
./ssghost666 -url https://app.anda.com
```

Contoh yang lebih lengkap:

```bash
./ssghost666 \
  -url https://app.anda.com \
  -depth 3 \
  -bearer "$TOKEN" \
  -openapi ./openapi.yaml \
  -js-render \
  -proxy http://127.0.0.1:8080 \
  -out laporan.html \
  -v
```

Jalankan `./ssghost666 -h` untuk daftar lengkap flag (target, auth, proxy,
discovery, checks, SSRF callback, dll).

### Memilih pemeriksaan tertentu

```bash
./ssghost666 -url https://app.anda.com -checks sqli,xss,passive
```

Nilai yang didukung: `sqli`, `xss`, `cmdi`, `ssrf`, `auth`, `passive`,
atau `all` (bawaan).

### Pengujian SSRF dengan callback OOB

```bash
./ssghost666 -url https://app.anda.com -ssrf-callback https://xxxx.oast.site
```

Alat ini akan mengirim payload berisi URL callback Anda ke parameter yang
kelihatan seperti menerima URL (`url`, `redirect`, `webhook`, dst), lalu
Anda konfirmasi manual lewat dashboard Collaborator/interactsh Anda —
SSGhost666 tidak bisa melihat panggilan OOB itu sendiri.

## Arsitektur singkat

```
main.go                     — merangkai semua fase
internal/options             — parsing flag CLI
internal/httpclient          — klien HTTP (proxy, auth, TLS, evidence mentah)
internal/ratelimiter         — rate limit + concurrency bersama
internal/browser             — peluncur tab headless Chrome bersama (dipakai crawler & scanner)
internal/crawler             — crawl statis, ekstraksi JS, discovery (+ kalibrasi soft-404), js-render (chromedp)
internal/openapi             — parser OpenAPI 3 / Swagger 2 → target, termasuk resolver $ref/allOf
internal/scanner             — setiap modul pemeriksaan + engine orkestrasi
  sqli.go                      error-based, boolean-based, time-based
  xss.go + xss_confirm.go      deteksi refleksi + konfirmasi eksekusi browser
  cmdi.go, ssrf.go, auth.go    command injection, SSRF, CORS/broken-access/JWT
  passive.go + jslibs.go       header/error/listing pasif + versi pustaka JS rentan
internal/report               — output terminal & laporan HTML
```

Setiap pemeriksaan aktif (`sqli.go`, `xss.go`, `cmdi.go`, `ssrf.go`,
bagian dari `auth.go`) memakai helper request bersama
(`scanner/request.go`) sehingga penanganan parameter query/path/body/
header/cookie konsisten di semua modul, dan *setiap* request HTTP
sungguhan — bukan hanya satu per parameter — melewati rate limiter yang
sama.

## Yang perlu dipahami (batasan)

- **ini alat deteksi, bukan kerangka eksploitasi.** Setiap pemeriksaan
  aktif memakai payload non-destruktif (tidak ada `DROP`/`DELETE`, tidak
  ada payload yang mencoba membuka shell sungguhan) dan berhenti begitu
  cukup bukti terkumpul untuk sebuah temuan.
- **Temuan adalah sinyal otomatis, bukan vonis akhir.** Terutama untuk
  *broken access control*: heuristiknya dibuat sepresisi mungkin (hanya
  menyala untuk endpoint yang terlihat seperti API JSON, dideklarasikan
  butuh auth di OpenAPI, atau path dengan kata kunci sensitif), tapi
  tetap bisa salah pada aplikasi dengan desain tidak biasa. Selalu
  verifikasi manual sebelum melaporkan ke pihak lain.
- **SSRF time-based/in-band** memerlukan server target benar-benar
  mencoba fetch; beberapa kasus hanya bisa dikonfirmasi lewat callback
  OOB (`-ssrf-callback`).
- **`-js-render` butuh Chrome/Chromium terpasang** di mesin yang
  menjalankan SSGhost666 — dipakai untuk fase crawling dinamis maupun
  untuk konfirmasi eksekusi XSS. Tanpa itu, alat akan memberi peringatan
  yang jelas dan melanjutkan sisa pemindaian tanpa fase-fase ini (temuan
  XSS tetap dilaporkan, hanya saja tetap berstatus "unconfirmed").
  Konfirmasi browser juga hanya berjalan untuk request **GET** lewat
  parameter **query/path**; payload XSS di body/header/cookie tetap
  dilaporkan berdasarkan refleksi HTTP saja (tidak dikonfirmasi lewat
  browser).
- **Basis data pustaka JS rentan bersifat statis dan offline** — berisi
  CVE yang sudah dikenal luas dan diverifikasi saat alat ini ditulis,
  bukan feed yang selalu ter-update. Perlakukan sebagai titik awal
  pemeriksaan, bukan daftar lengkap.
- Brute-force discovery memakai wordlist bawaan yang sengaja kecil.
  Untuk cakupan lebih luas, arahkan `-wordlist` ke daftar yang lebih
  besar (mis. dari SecLists).

## Mengembangkan lebih lanjut

Empat arah perluasan yang sebelumnya tercatat di sini — boolean-based
blind SQLi, konfirmasi XSS lewat eksekusi nyata di headless Chrome,
pencocokan versi pustaka JS rentan, dan dukungan `$ref`/`allOf` penuh
pada OpenAPI — semuanya **sudah diimplementasikan** (lihat daftar fitur
di atas). Setiap fitur sudah diuji nyata: boolean-blind dan time-based
SQLi divalidasi hingga terbukti saling tidak kontaminasi silang (payload
bergaya SQL tidak salah memicu temuan command injection dan sebaliknya),
konfirmasi XSS divalidasi dengan Chrome sungguhan hingga benar-benar
mengeksekusi script yang disuntik, deteksi pustaka JS diuji dengan 11
skenario (banner per pustaka, fallback nama file, batas versi persis),
dan resolver OpenAPI diuji dengan dokumen yang memakai `$ref` bersarang
di dalam `allOf`.

Arah perluasan lain yang masih masuk akal jika ingin melanjutkan:

- **Konfirmasi SSRF in-band yang lebih kaya** — saat ini deteksi
  in-band mengandalkan marker metadata cloud yang dikenal (`ami-id`,
  `computeMetadata`, dst) atau perbedaan status/waktu terhadap kontrol;
  bisa diperluas dengan listener callback lokal bawaan (bukan hanya
  menerima URL OOB eksternal via `-ssrf-callback`) untuk kasus pentest
  jaringan internal di mana target bisa menjangkau balik mesin pemindai.
- **DOM-based XSS** (bukan cuma reflected) — memeriksa sink berbahaya
  (`innerHTML`, `document.write`, dst) yang dipicu oleh data dari
  `location.hash`/`postMessage` tanpa pernah menyentuh server sama
  sekali; headless Chrome yang sudah terpasang (`internal/browser`)
  adalah fondasi yang tepat untuk ini.
- **Autentikasi multi-langkah** (login form → ekstrak token/cookie CSRF
  → gunakan di request berikutnya) untuk target yang sesi awalnya tidak
  bisa diwakili satu cookie/bearer token statis saja.
- **Basis data pustaka JS yang bisa diperbarui** — tabel
  `knownVulnJSLibs` di `internal/scanner/jslibs.go` saat ini statis
  dan ter-embed di source; bisa dibuat agar bisa memuat basis data
  tambahan dari file eksternal tanpa perlu rebuild.

Lisensi: MIT Gagaltotal666 - GhostGTR666.