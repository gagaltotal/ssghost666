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
- **Sesi terautentikasi fleksibel**: 
  - **Autentikasi sederhana**: `-cookie`, `-bearer`, atau `-header` kustom (bisa diulang) untuk sesi yang sudah terbentuk.
  - **Autentikasi multi-langkah** (`-auth-flow`): file JSON yang mendefinisikan alur login kompleks (form login → ekstrak CSRF token → submit kredensial → ekstrak session cookie). Mendukung ekstraksi token dari cookie, header, JSON response, regex, atau field HTML input. Bisa menggunakan HTTP biasa atau headless browser untuk halaman yang bergantung pada JavaScript. Lihat `auth-flow-example.json` untuk template lengkap.
- **Proxy**: `-proxy http://127.0.0.1:8080` untuk merutekan semua trafik lewat Burp/ZAP/mitmproxy agar bisa dipantau langsung.
- **Pemeriksaan aktif SQL injection**, tiga teknik berjenjang (tercepat dicoba dulu, teknik berikutnya hanya jalan jika yang sebelumnya nihil):
  1. *Error-based* — payload pemecah sintaks, cari signature error database di respons.
  2. *Boolean-based blind* — kirim pasangan payload true/false, bandingkan respons; perlu **dua pasangan independen** yang konsisten sebelum dilaporkan, supaya halaman yang sekadar sedikit berubah antar-request tidak dikira rentan.
  3. *Time-based blind* — payload yang membuat database "tidur", dengan **konfirmasi ganda** (request diulang) sebelum dilaporkan.
- **Reflected XSS dengan konfirmasi eksekusi nyata**: deteksi awal lewat refleksi payload di respons HTTP (cepat, tanpa browser). Jika `-js-render` diaktifkan dan hit-nya berupa request GET lewat parameter query/path, SSGhost666 melangkah lebih jauh — membuka tab headless Chrome sungguhan, navigasi ke URL persis yang memicu refleksi, lalu memeriksa apakah skrip yang disuntik **benar-benar tereksekusi** (bukan cuma cocok teks). Temuan yang terkonfirmasi lewat eksekusi browser naik ke severity Critical dan ditandai jelas "(executed in browser)"; yang cuma refleksi tanpa bisa dikonfirmasi tetap dilaporkan tapi ditandai "(unconfirmed — reflection only)". Ini juga otomatis menyaring positif-palsu sebaliknya: payload yang "terlihat" reflected di teks mentah tapi ternyata jatuh di konteks mati (dalam komentar HTML, misalnya) akan ketahuan tidak benar-benar jalan.
- **DOM-based XSS detection** (`-dom-xss`): memeriksa sink berbahaya JavaScript (`innerHTML`, `document.write`, `eval`, `location.href`, dst) yang dipicu oleh data dari sumber DOM (`location.hash`, `location.search`, `postMessage`) tanpa pernah menyentuh server. Menggunakan headless Chrome dengan instrumentasi untuk mendeteksi aliran data dari sumber ke sink, plus konfirmasi eksekusi payload melalui dialog `alert()`. Cocok untuk aplikasi SPA modern yang memproses input sepenuhnya di sisi klien.
- **OS command injection** (time-based blind, konfirmasi ganda) dan **SSRF yang lebih kaya**: 
  - **Listener callback lokal bawaan** (`-ssrf-listener`, aktif secara default) — SSGhost666 menjalankan server HTTP kecil di mesin Anda dan menggunakan IP lokal sebagai target SSRF. Jika server target berhasil menghubungi balik listener ini, SSRF langsung terkonfirmasi tanpa perlu layanan eksternal. Sempurna untuk pentest jaringan internal di mana target bisa menjangkau mesin pemindai.
  - **Deteksi in-band ke metadata cloud** — mencocokkan marker metadata AWS/GCP/Azure di respons (dengan penyaringan agar endpoint yang sekadar meng-echo input tidak salah terdeteksi).
  - **Dukungan callback OOB eksternal** (`-ssrf-callback`) — untuk kasus di mana target hanya bisa keluar ke internet publik (Burp Collaborator, interact.sh, dsb).
- **Pemeriksaan autentikasi**: kesalahan konfigurasi CORS, indikasi broken access control (dibandingkan dengan & tanpa kredensial, disaring agar tidak berisik di halaman publik biasa), flag keamanan cookie, decode JWT (mendeteksi `alg: none`, klaim `exp` yang hilang).
- **Pemeriksaan pasif**: header keamanan yang hilang, kebocoran versi lewat header `Server`/`X-Powered-By`, stack trace/error verbose, directory listing, mixed content, **dan pustaka JavaScript dengan versi yang diketahui rentan** (jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, Handlebars, Underscore.js, AngularJS — dicocokkan dari banner versi di file JS atau nama filenya, terhadap tabel CVE publik yang sudah diverifikasi, masing-masing dengan referensi CVE dan saran upgrade).
- **Basis data pustaka JS yang dapat diperbarui** (`-jslibs-db`): tabel CVE bawaan (built-in) dapat diperluas dengan file JSON eksternal tanpa perlu rebuild. Letakkan file database kustom Anda (lihat `jslibs-db-example.json`) di sebuah direktori, lalu gunakan `-jslibs-db /path/to/db-dir`. Database eksternal akan digabungkan dengan database bawaan saat pemindaian dimulai. Cocok untuk menambahkan CVE terbaru atau pustaka internal/proprietary.
- **Output terminal berwarna**, langsung terbaca, dengan temuan dicetak live saat ditemukan.
- **Laporan HTML** (`-out report.html`) mandiri (tanpa dependensi eksternal) berisi bukti request/response lengkap per temuan, dengan auto-escaping yang benar (payload yang direfleksikan tidak akan "hidup" sebagai HTML di laporan) dan redaksi otomatis header `Authorization`/`Cookie` (nonaktifkan dengan `-no-redact`).
- **Rate limiting & concurrency yang sopan secara default** (`-rate`, `-concurrency`, `-max-requests`) — setiap request HTTP sungguhan melewati limiter yang sama, bukan hanya longgar per "tugas".

## Instalasi

### Instalasi Otomatis (Semua Distro Linux)

Script instalasi otomatis mendukung Ubuntu, Debian, Fedora, RHEL, CentOS, Arch Linux, openSUSE, Alpine, dan distro lainnya:

```bash
cd ssghost666
chmod +x install.sh
sudo ./install.sh
```

Script akan:
- Mendeteksi distro Linux Anda secara otomatis
- Menginstal Go 1.23+ (jika belum ada atau versi terlalu lama)
- Menginstal Chrome/Chromium (opsional, untuk fitur `-js-render` dan `-dom-xss`)
- Mem-build dan menginstal SSGhost666 ke `/usr/local/bin`
- Menyalin file contoh konfigurasi ke `/etc/ssghost666`

Setelah instalasi, Anda bisa langsung menjalankan:

```bash
ssghost666 -url https://target.com
```

### Build Manual

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

#### Instalasi Manual ke Sistem

```bash
sudo cp ssghost666 /usr/local/bin/
sudo chmod +x /usr/local/bin/ssghost666
```

## Pemakaian

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/ssghost666/refs/heads/main/images/Screenshot%20from%202026-10-08%2000-12-37.png)

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

### Fitur Lanjutan

#### SSRF dengan Listener Lokal

Secara default, SSGhost666 menjalankan listener HTTP lokal untuk deteksi SSRF in-band:

```bash
./ssghost666 -url https://app.anda.com
# Listener otomatis dimulai, misal di http://192.168.1.100:54321
```

Jika target berhasil memanggil balik listener, SSRF langsung terkonfirmasi. Nonaktifkan dengan `-ssrf-listener=false` jika tidak diperlukan.

#### DOM-based XSS Detection

Aktifkan pemeriksaan DOM XSS untuk aplikasi yang banyak memproses data di sisi klien:

```bash
./ssghost666 -url https://app.anda.com -dom-xss
```

Memerlukan Chrome/Chromium. Alat akan menguji payload via URL fragment (`#<payload>`) dan memantau penggunaan sink berbahaya.

#### Autentikasi Multi-Langkah

Untuk aplikasi dengan alur login kompleks, buat file JSON yang mendefinisikan langkah-langkahnya:

```bash
./ssghost666 -url https://app.anda.com -auth-flow ./my-auth-flow.json
```

Contoh `my-auth-flow.json`:

```json
{
  "steps": [
    {
      "name": "Get CSRF token",
      "url": "https://app.anda.com/login",
      "method": "GET",
      "extractors": [
        {
          "name": "CSRF Token",
          "type": "input",
          "pattern": "csrf_token",
          "storeAs": "csrf",
          "required": true
        }
      ]
    },
    {
      "name": "Submit login",
      "url": "https://app.anda.com/login",
      "method": "POST",
      "formData": {
        "username": "testuser",
        "password": "testpass",
        "csrf_token": "{{csrf}}"
      },
      "extractors": [
        {
          "name": "Session",
          "type": "cookie",
          "pattern": "session",
          "storeAs": "cookie_session",
          "required": true
        }
      ]
    }
  ]
}
```

Lihat `auth-flow-example.json` untuk template lengkap dengan semua opsi.

#### Database Pustaka JS Kustom

Perbarui database CVE pustaka JavaScript tanpa rebuild:

```bash
mkdir ~/jslibs-db
# Letakkan file JSON kustom di sini (lihat jslibs-db-example.json)
./ssghost666 -url https://app.anda.com -jslibs-db ~/jslibs-db
```

Format file JSON:

```json
{
  "version": "1.0",
  "last_updated": "2024-01-15",
  "vulnerabilities": [
    {
      "library": "React",
      "fixed_version": "16.4.2",
      "cve": "CVE-2018-6341",
      "description": "XSS via malicious iframe",
      "severity": "high"
    }
  ]
}
```

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

### Fitur yang Sudah Diimplementasikan

Fitur-fitur berikut yang sebelumnya direncanakan **sudah selesai diimplementasikan**:

1. **SSRF in-band dengan listener callback lokal** — SSGhost666 kini menjalankan server HTTP lokal otomatis untuk menerima callback SSRF langsung dari target, sempurna untuk pentest jaringan internal.
2. **DOM-based XSS detection** — deteksi penuh sink berbahaya JavaScript (`innerHTML`, `eval`, `document.write`, dst) yang dipicu dari sumber DOM (`location.hash`, `postMessage`) dengan konfirmasi eksekusi via headless Chrome.
3. **Autentikasi multi-langkah** — framework lengkap untuk alur login kompleks dengan ekstraksi token CSRF, session cookies, dan dukungan JavaScript via headless browser.
4. **Basis data pustaka JS yang updatable** — database CVE kini bisa diperluas dengan file JSON eksternal tanpa rebuild, mendukung update terbaru dan pustaka proprietary.

Setiap fitur sudah diuji production-ready: boolean-blind dan time-based SQLi divalidasi hingga terbukti saling tidak kontaminasi silang, konfirmasi XSS divalidasi dengan Chrome sungguhan hingga benar-benar mengeksekusi script yang disuntik, deteksi pustaka JS diuji dengan 11 skenario, dan resolver OpenAPI diuji dengan dokumen yang memakai `$ref` bersarang di dalam `allOf`.

### Roadmap Pengembangan Selanjutnya

Arah perluasan yang masih masuk akal untuk meningkatkan kemampuan SSGhost666:

#### Deteksi & Eksploitasi Lanjutan

- **Blind XSS dengan storage callback** — payload XSS yang tersimpan di database dan ter-trigger kemudian (misalnya di admin panel), dengan polling otomatis ke callback server untuk mendeteksi eksekusi tertunda. Berguna untuk stored XSS yang sulit dideteksi langsung.

- **SSTI (Server-Side Template Injection)** — deteksi template engine (Jinja2, Twig, Freemarker, Velocity, dst) via payload matematika sederhana dan signature error, lalu konfirmasi dengan payload yang lebih spesifik per-engine.

- **XXE (XML External Entity)** — parser XML yang menerima DTD eksternal, diuji dengan payload yang mencoba baca file lokal (`/etc/passwd`) atau trigger DNS callback untuk konfirmasi out-of-band.

- **Insecure deserialization** — deteksi signature serialized object (Java, Python pickle, PHP serialize, .NET BinaryFormatter) di parameter/header, plus payload sleep-based untuk konfirmasi eksekusi kode.

- **GraphQL introspection & injection** — deteksi endpoint GraphQL, ekstrak schema via introspection query, lalu fuzz mutation/query untuk SQL injection, authorization bypass, dan information disclosure.

- **WebSocket security testing** — crawl WebSocket endpoints dari JavaScript, uji authentication bypass, message injection, dan rate limiting pada real-time communication.

#### Smart Fuzzing & AI

- **Context-aware fuzzing** — analisis parameter berdasarkan nama/tipe untuk memilih payload yang lebih relevan (parameter `email` → email injection payloads, `id` → IDOR/SQLi numeric, `file` → path traversal).

- **Machine learning untuk false positive reduction** — model ML yang belajar dari historical scan results untuk membedakan true positive vs false positive berdasarkan response patterns, mengurangi manual verification.

- **Mutasi payload otomatis** — jika payload ditolak WAF/filter, generator otomatis mencoba encoding alternatif (hex, unicode, double encoding, case variation) dan teknik obfuscation untuk bypass.

#### Authentication & Authorization

- **JWT fuzzing lanjutan** — selain `alg: none`, coba weak signing keys (brute-force HS256 secret), algorithm confusion (RS256→HS256), claim manipulation, dan token expiration abuse.

- **OAuth/OIDC flow testing** — deteksi authorization code interception, redirect_uri validation bypass, PKCE missing, state parameter abuse, dan token leakage.

- **Session management testing** — predictable session ID, session fixation, concurrent session limits, session timeout yang terlalu panjang, dan cookie scope issues.

#### API Security

- **REST API mass assignment** — deteksi parameter yang bisa dimanipulasi untuk mengubah field protected (role, isAdmin, price) dengan membandingkan response normal vs modified.

- **Rate limiting & resource exhaustion** — deteksi endpoint tanpa rate limit yang bisa di-abuse untuk DoS, atau endpoint expensive (file upload, report generation) tanpa proteksi.

- **API versioning issues** — scan multiple API versions (`/v1/`, `/v2/`) untuk menemukan versi lama yang masih aktif tapi tidak ter-maintain dengan vulnerability yang sudah dipatch di versi baru.

#### Infrastructure & DevOps

- **Cloud misconfiguration scanner** — deteksi S3 bucket public, exposed `.git`/`.env`/`.aws` directories, Kubernetes dashboard tanpa auth, Docker API exposed, dan cloud metadata endpoints.

- **Subdomain takeover** — crawl subdomain via DNS, cek CNAME pointing ke layanan yang sudah di-deprovision (GitHub Pages, Heroku, AWS S3, Azure, dll), lalu verifikasi apakah bisa di-claim.

- **SSL/TLS testing** — analisis cipher suite weak, protocol version lama (SSLv3, TLS 1.0), certificate validation issues, dan Heartbleed/POODLE/BEAST vulnerability.

#### Reporting & Integration

- **Diff mode untuk CI/CD** — bandingkan hasil scan dengan baseline sebelumnya, laporkan hanya temuan baru untuk integrasi dengan pipeline CI/CD tanpa noise.

- **Export ke format standar** — selain HTML, support JSON/CSV/SARIF untuk integrasi dengan SIEM, bug tracking (Jira, GitHub Issues), atau security platform (DefectDojo, Faraday).

- **Slack/Discord/Telegram notification** — kirim alert real-time saat menemukan critical/high findings, dengan summary singkat dan link ke full report.

- **Collaborative scanning** — multiple scanner instances bisa koordinasi lewat shared queue (Redis/RabbitMQ) untuk scan target besar secara distributed, dengan deduplication otomatis.

#### Performance & Scalability

- **Adaptive rate limiting** — otomatis turunkan rate jika detect response time naik (server under load) atau error rate meningkat, lalu naikkan lagi saat kondisi normal.

- **Smart crawling** — deteksi pagination pattern otomatis (`?page=`, `?offset=`), infinite scroll via JavaScript, dan skip duplicate content (same response hash) untuk efisiensi.

- **Resume capability** — simpan state scan ke file sehingga bisa di-pause dan di-resume nanti, berguna untuk scan jangka panjang atau connection interrupted.

### Kontribusi yang Diharapkan

Jika Anda ingin berkontribusi, prioritas tertinggi adalah:

1. **Testing & bug reports** — uji di berbagai aplikasi web nyata, laporkan false positives/negatives
2. **Payload database** — tambahkan CVE terbaru ke `jslibs-db`, atau payload bypass untuk WAF populer
3. **Documentation** — tutorial lengkap, video walkthrough, atau case study penggunaan di pentest nyata
4. **Platform support** — port ke Windows/macOS jika ada yang butuh, atau Docker image untuk portability

Pull requests untuk fitur di roadmap sangat diterima — pastikan include test cases dan documentation!

Lisensi: MIT Gagaltotal666 - GhostGTR666.