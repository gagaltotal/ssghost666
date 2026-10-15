# SSGhost666

Pemindai keamanan web berbasis CLI, ditulis dalam Go. Fokusnya adalah
**pengumpulan bukti** (evidence gathering) terhadap aplikasi web yang Anda
miliki atau telah mendapat izin eksplisit untuk diuji: menemukan
halaman/endpoint, meng-crawl rute yang dimuat JavaScript, mengimpor
definisi API, lalu menjalankan pemeriksaan terarah untuk SQL injection,
XSS (termasuk blind/stored), command injection, SSRF, SSTI, XXE, insecure
deserialization, GraphQL, WebSocket, JWT/OAuth/session, SSO/SAML provider
abuse, cloud misconfiguration, subdomain takeover, SSL/TLS configuration,
masalah autentikasi, dan beberapa pemeriksaan pasif — dengan setiap temuan
membawa bukti request/response mentah. Hasil pemindaian bisa diekspor ke
HTML, JSON, CSV, atau SARIF.

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
- **Blind (stored) XSS dengan storage callback** (`-checks blindxss`): payload beacon berisi marker unik disuntik ke parameter yang cenderung disimpan (nama, komentar, email, dst). Karena stored XSS baru tereksekusi saat admin/other user membuka halaman yang menyimpannya, SSGhost666 menjalankan **listener callback lokal** (`-blind-xss-listener`, aktif default) yang menyajikan JS beacon dan mencatat eksekusi dari browser korban — lengkap dengan cookie, URL, referer, user-agent, dan cuplikan HTML halaman. Callback yang datang terlambat tetap tertangkap oleh sweep akhir di ujung pemindaian.
- **SSTI (Server-Side Template Injection)** (`-checks ssti`): dua tingkat. Pertama probe aritmatika lintas-engine (`{{7331*7331}}`, `${...}`, `#{...}`, `<%= ... %>`, `*{...}`) — kalau hasilnya (`53743061`) muncul di respons, input mencapai template engine. Kedua, konfirmasi per-engine (Jinja2 `{{7*'7'}}`→`7777777`, Twig→`49`, Freemarker, Velocity, ERB, Smarty) plus pencocokan signature error template, sehingga temuan menyebut engine spesifiknya, bukan sekadar "ada SSTI".
- **XXE (XML External Entity)** (`-checks xxe`): hanya menyentuh endpoint yang memang memproses XML (URL `.xml`/`soap`/`wsdl`, Content-Type XML, atau punya body param terstruktur). Tier 1 mencoba baca file lokal (`/etc/passwd`, `/etc/hostname`, `C:\Windows\win.ini`) dengan DOCTYPE external entity; Tier 2 memakai **listener callback OOB lokal** (`-oob-listener`, aktif default) untuk konfirmasi blind XXE saat tidak ada konten file yang direfleksikan.
- **Insecure deserialization** (`-checks deser`): mengenali signature serialized object (Java `rO0AB`, PHP `O:8:`/`a:2:{`, .NET `AAEAAAD/////`) di parameter/header, lalu menyuntik payload serialized ber-marker dan mendeteksi **error deserialization** yang tidak ada di baseline (`InvalidClassException`, `UnpicklingError`, `unserialize()`, `SerializationException`, dst). Jika signature serialized sudah terlihat, payload pickle `sleep` non-destruktif dipakai untuk **konfirmasi eksekusi kode** dengan dua request independen.
- **GraphQL introspection & injection** (`-checks graphql`): menemukan endpoint GraphQL dari path yang di-crawl maupun path konvensional (`/graphql`, `/api/graphql`, `/gql`, `/graphiql`, dst) per origin, lalu mendeteksi apakah endpoint benar-benar GraphQL (respons error berbentuk GraphQL untuk query yang rusak). Setelah itu: **introspection query** untuk mengukur paparan schema, **authorization bypass** (query yang sama berhasil tanpa kredensial), **error-based SQLi** di variabel resolver, dan **information disclosure** lewat stack trace/debug di error channel.
- **WebSocket security testing** (`-checks websocket`): endpoint WebSocket dikumpulkan dua arah — literal `ws://`/`wss://` di file JS (analisis statis) dan event jaringan browser saat `-js-render` (`EventWebSocketCreated`). Dites dengan klien RFC 6455 minimal (tanpa dependensi eksternal): keberadaan handshake, **authentication bypass** (handshake tanpa kredensial), **Origin validation / CSWSH** (handshake dengan Origin domain asing), **message injection/reflection** (marker dipantulkan kembali, primitif DOM XSS), dan **rate limiting** (flood pesan tanpa throttling).
- **Pemeriksaan pasif**: header keamanan yang hilang, kebocoran versi lewat header `Server`/`X-Powered-By`, stack trace/error verbose, directory listing, mixed content, **dan pustaka JavaScript dengan versi yang diketahui rentan** (jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, Handlebars, Underscore.js, AngularJS — dicocokkan dari banner versi di file JS atau nama filenya, terhadap tabel CVE publik yang sudah diverifikasi, masing-masing dengan referensi CVE dan saran upgrade).
- **Basis data pustaka JS yang dapat diperbarui** (`-jslibs-db`): tabel CVE bawaan (built-in) dapat diperluas dengan file JSON eksternal tanpa perlu rebuild. Letakkan file database kustom Anda (lihat `jslibs-db-example.json`) di sebuah direktori, lalu gunakan `-jslibs-db /path/to/db-dir`. Database eksternal akan digabungkan dengan database bawaan saat pemindaian dimulai. Cocok untuk menambahkan CVE terbaru atau pustaka internal/proprietary.
- **Output terminal berwarna**, langsung terbaca, dengan temuan dicetak live saat ditemukan.
- **Laporan HTML** (`-out report.html`) mandiri (tanpa dependensi eksternal) berisi bukti request/response lengkap per temuan, dengan auto-escaping yang benar (payload yang direfleksikan tidak akan "hidup" sebagai HTML di laporan) dan redaksi otomatis header `Authorization`/`Cookie` (nonaktifkan dengan `-no-redact`).
- **Rate limiting & concurrency yang sopan secara default** (`-rate`, `-concurrency`, `-max-requests`) — setiap request HTTP sungguhan melewati limiter yang sama, bukan hanya longgar per "tugas".
- **Mutasi payload otomatis (bypass WAF/filter)** (`-mutate-payload`, aktif default): saat sebuah payload ditolak WAF/filter — terdeteksi dari status blok (403/406/419/429/501/999) atau signature WAF yang dikenal (Cloudflare, AWS WAF, ModSecurity, Sucuri, Imperva, Akamai, F5, Barracuda, Wordfence) di header maupun body — SSGhost666 otomatis mengirim ulang payload yang sama dalam beberapa varian encoding/obfuscation (case variation, SQL comment whitespace `UNION/**/SELECT`, full URL-encoding, double URL-encoding, HTML hex entities, unicode escapes) dan memakai varian pertama yang lolos untuk logika deteksinya. Setiap temuan mencatat varian mana saja yang dicoba. Nonaktifkan dengan `-mutate-payload=false`.
- **JWT fuzzing lanjutan** (`-checks jwt`, memakai `-bearer`): selain deteksi `alg: none`, modul ini membongkar token untuk **brute-force weak HS256 secret** (~130 secret bocor/umum seperti `secret`, `changeme`, `jwt-secret`, kunci contoh dari dokumentasi), **algorithm confusion RS256→HS256** (mengambil public key dari JWKS endpoint `/.well-known/jwks.json` atau OIDC discovery, lalu menandatangani token palsu dengan kunci publik sebagai HMAC secret), **klaim escalation** (`role`/`admin`/`isAdmin` dinaikkan, `sub`/`user` diubah) dan **ekspirasi** (`exp` dihilangkan, `iss`/`aud` dikosongkan). Token forged hanya dianggap berhasil setelah **kontrol negatif** (token sengaja rusak) ditolak target — jadi server yang menerima semua token tidak menghasilkan false positive.
- **OAuth / OIDC flow testing** (`-checks oauth`): menemukan endpoint authorization (dari crawl maupun path konvensional `/oauth/authorize`, `/auth`, `/login`, dst), lalu menguji **redirect_uri validation bypass** dengan 10 varian (suffix/prefix abuse, `@`-trick, subdomain, open redirect bertingkat, path traversal, dan lainnya), **PKCE missing** (tidak ada `code_challenge`), **state parameter abuse** (state hilang atau bisa diprediksi), dan **token/code leakage** lewat `Location` header atau `Referer`.
- **Session management testing** (`-checks session`): menganalisis cookie sesi yang tertangkap dan melaporkan **session ID yang lemah** (entropi Shannon rendah, nilai sekuensial/prediktabel, nilai bernama `JSESSIONID=1001` dsb), **flag keamanan cookie** yang hilang (`HttpOnly`/`Secure`/`SameSite`), **masa berlaku berlebihan** (`Max-Age`/`Expires` terlalu panjang), **scope cookie** yang terlalu luas (`Domain`/`Path`), dan indikasi **session fixation** (nilai sesi tidak berubah setelah request ber-kredensial).
- **Adaptive rate limiting** (`-adaptive-rate`, aktif default): limiter mengamati latensi, status, dan error tiap request dengan baseline bergerak (EWMA), lalu menurunkan rate saat target melambat atau mulai membalas error/429/5xx (hingga 1/5 rate awal) dan menaikkannya kembali saat respons sehat lagi (maksimum 2x rate awal). Nonaktifkan dengan `-adaptive-rate=false`.
- **Smart crawling** (`-smart-crawl`, aktif default): mendeteksi pola pagination numerik umum (`?page=`, `?p=`, `?offset=`, `?start=`, `?skip=`, `?from=`, dst) dan otomatis mengantre halaman berikutnya (nilai +1/+2, dibatasi 5 URL per halaman agar tetap terarah, bukan crawl arsip tanpa batas). Digabung dengan **suppression konten duplikat** berbasis hash respons (sha256) — halaman yang isinya identik di banyak URL (SPA shell, pagination yang "menjepit" di halaman terakhir) tidak di-crawl dan tidak dipindai berulang. Nonaktifkan dengan `-smart-crawl=false`.
- **Resume capability** (`-resume state.json`): status scan (URL yang sudah dikunjungi + hash konten yang sudah dilihat) disimpan ke file JSON dan dimuat ulang saat dijalankan kembali, sehingga scan jangka panjang yang terputus (atau sengaja di-pause dengan Ctrl-C) bisa dilanjutkan tanpa mengulang crawl dari awal. Penulisan bersifat atomik (tulis ke file sementara lalu `rename`), dan state untuk target yang berbeda otomatis diabaikan agar tidak salah melewati halaman.
- **SSO/OAuth provider abuse lanjutan** (`-checks sso`): melengkapi pengujian OAuth/OIDC dengan sisi **provider**. Menemukan metadata SAML ( `/saml/metadata`, `/sso/metadata`, `/FederationMetadata/...`), ACS endpoint ( `/saml/acs`, `/Shibboleth.sso/SAML2/POST`), dan JWKS/OIDC discovery ( `/.well-known/jwks.json`, `/.well-known/openid-configuration`) dari hasil crawl maupun path konvensional. Lalu menguji **SAML response manipulation**: assertion tanpa signature, assertion dengan signature yang sengaja dirusak, dan assertion `unsigned` dengan `ds:Signature` kosong — masing-masing dibandingkan dengan **kontrol negatif** sehingga hanya server yang benar-benar menerima assertion palsu (tanpa memverifikasi XML signature) yang dilaporkan, dan **RelayState open redirect**. Untuk JWT, ia memeriksa JWKS yang **mempublikasikan kunci `kty: oct`** (secret HMAC yang bocor, sehingga siapa pun bisa menandatangani token yang valid — dilengkapi pembuktian end-to-end dengan token yang benar-benar di-forge), **`kid` header injection** (path traversal `../../../../dev/null` sehingga signature jadi HMAC dari kunci kosong, dan SQL error di nilai `kid`).
- **Cloud misconfiguration scanner** (`-checks cloud`): satu gerbang untuk kesalahan konfigurasi cloud yang paling sering berbuah kebocoran. (a) **File sensitif yang terpapar** — `/.git/config`, `/.git/HEAD`, `/.env`, `/.aws/credentials`, `/.htpasswd`, `/.DS_Store`, `docker-compose.yml` — tiap-tiap path punya **validator format** sendiri (pola `[core]`/`[remote "..."]`, `ref: refs/heads/`, pasangan `KEY=VALUE` khas `.env`, blok `[default]` AWS, hash bcrypt/apr1, magic bytes `Bud1`), jadi respons HTML catch-all tidak akan pernah lolos. (b) **Layanan admin tanpa autentikasi** — Kubernetes API (`/api/v1/namespaces`, `/version`), Docker API (`/api/version`), Consul (`/v1/agent/self`, `/v1/catalog/services`) — dilaporkan **kritis** hanya jika respons benar-benar parse sebagai JSON dari layanan tersebut. (c) **Swagger/OpenAPI yang terbuka** yang mengungkap peta API internal. (d) **Cloud metadata endpoint (SSRF ke IMDS)** — mencoba `169.254.169.254` (AWS), `metadata.google.internal` + header `Metadata-Flavor: Google` (GCP), Azure IMDS dengan header `Metadata: true`, dan Alibaba — dijalankan per-origin dengan marker khusus masing-masing, sehingga tidak menyalahkan web server biasa sebagai metadata service. (e) **S3 bucket publik** — daftar bucket diekstrak dari markup crawl, lalu hanya yang menghasilkan `ListBucketResult` sah dan **tidak** mengandung hint non-bucket (CloudFront, ELB, execute-api) yang dilaporkan.
- **Subdomain takeover** (`-checks subdomain`): mengambil setiap hostname yang muncul selama crawl (plus host target itu sendiri), menelusuri rantai **CNAME** dengan resolver stdlib (`net.LookupCNAME`, maksimum 8 hop dan anti-loop), lalu mencocokkan suffix CNAME terhadap **tabel 31 penyedia** (GitHub Pages, Heroku, AWS S3/CloudFront, Azure, Netlify, Vercel, Shopify, Fastly, Zendesk, Tumblr, WordPress.com, Ghost, Surge.sh, Read the Docs, Bitbucket, Pantheon, Statuspage, Unbounce, Freshdesk, Teamwork, Desk.com, SmugMug, Cargo, Kajabi, Agile CRM, Ngrok, Fly.io, Render, GitLab Pages, Firebase, dst). **CNAME dangling saja bukan temuan** — ini yang membedakannya dari scanner yang berisik: setiap kandidat harus benar-benar mengembalikan **halaman error "resource tidak ada" spesifik penyedia** (setiap signature memuat penanda penyedia, sehingga frasa generik seperti "not found" tidak pernah lolos sendiri), dan respons 5xx selalu ditolak karena itu outage, bukan resource menggantung. Pemeriksaannya **read-only** — SSGhost666 tidak pernah mencoba mengklaim atau mendaftarkan resource apa pun; bukti temuan menyebutkan bahwa konfirmasi dilakukan non-destruktif.
- **SSL/TLS testing** (`-checks tls`): menganalisis transport security tiap endpoint (host:port, dicap 6 endpoint). (a) **Versi protokol lama** — SSLv3, TLS 1.0, TLS 1.1 — dideteksi dengan **ClientHello mentah** yang dibuat sendiri (Go `crypto/tls` menolak SSLv3 dan minimum default-nya TLS 1.2, jadi pertanyaan "apakah server masih menerima TLS 1.0?" tidak bisa dijawab pustaka standar); ServerHello yang menggemakan versi yang ditawarkan membuktikan minimum server memang di bawahnya — TLS 1.0 dilaporkan dengan konteks **BEAST** (CVE-2011-3389), SSLv3 dengan konteks **POODLE** (CVE-2014-3566). (b) **Cipher suite rusak** — tiap keluarga lemah (NULL, EXPORT/40-bit, RC4, single DES, 3DES/**Sweet32**) ditawarkan **sendirian** pada TLS 1.2, jadi handshake yang berhasil adalah bukti suite itu memang masih aktif (bukan sekadar ada di daftar). (c) **Masalah certificate** — kedaluwarsa, belum berlaku, nama host tidak cocok, chain tidak tepercaya/self-signed, signatur **MD5/SHA-1**, dan kunci **RSA < 2048 bit** atau kurva ECDSA < 224 bit — masing-masing dibedakan penyebabnya alih-alih digabung jadi satu error handshake buram, dengan verifikasi trust-chain dihormati oleh `-insecure`. **Heartbleed sengaja tidak diuji**: konfirmasinya butuh mengirim heartbeat cacat dan membocorkan memori target, sedangkan SSGhost666 non-destruktif — keterbatasan ini dinyatakan eksplisit, bukan diabaikan diam-diam.
- **Export ke format standar** (`-out-format`): selain HTML, laporan bisa ditulis sebagai **JSON** (array temuan lengkap dengan metadata run, `severity_counts`, dan evidence redacted), **CSV** (RFC 4180 dengan header kolom tetap, aman untuk impor massal ke spreadsheet/Jira), atau **SARIF 2.1.0** (schema resmi, satu `rule` per kategori temuan, `level` dipetakan CRITICAL/HIGH→`error`, MEDIUM→`warning`, LOW/INFO→`note`, `partialFingerprints` berisi hash sha256 dari identitas temuan sehingga triage tersimpan antar-run) — format yang langsung dimakan GitHub code scanning, Azure DevOps, DefectDojo, Faraday, dan pipeline SIEM. Gunakan `-out-format auto` (bawaan) agar format ditentukan dari ekstensi file (`.json`, `.csv`, `.sarif`, `.sarif.json`, `.html`), atau paksa dengan `-out-format json|csv|sarif|html`. Redaksi `Authorization`/`Cookie` juga berlaku untuk JSON/CSV/SARIF, jadi format machine-readable tidak lebih bocor daripada HTML.

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

Nilai yang didukung: `sqli`, `xss`, `cmdi`, `ssrf`, `ssrfadvanced`, `auth`, `passive`,
`ssti`, `xxe`, `deser`, `graphql`, `websocket`, `blindxss`, `protopollution`,
`massassignment`, `ratelimiting`, `apiversioning`, `jwt`, `oauth`, `session`,
`sso`, `cloud`, `subdomain`, `tls`,
atau `all` (bawaan).

Contoh untuk API security testing:
```bash
./ssghost666 -url https://api.app.com -checks massassignment,ratelimiting,apiversioning,auth
```

Contoh untuk pengujian infrastruktur (SSO, cloud, subdomain, TLS):
```bash
./ssghost666 -url https://app.anda.com -checks sso,cloud,subdomain,tls
```

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

#### Blind XSS dengan Listener Lokal

Listener blind-XSS menyajikan beacon dan mencatat eksekusi tertunda dari browser korban:

```bash
./ssghost666 -url https://app.anda.com -checks blindxss
# Listener otomatis dimulai, misal di http://192.168.1.100:54321
```

Payload disuntikkan ke parameter yang cenderung disimpan; begitu seorang admin membuka halaman yang memuatnya, callback datang dan temuan langsung dilaporkan (termasuk cookie, URL, dan referer korban). Nonaktifkan dengan `-blind-xss-listener=false`.

#### Callback Out-of-Band (XXE / server-side blind)

Untuk konfirmasi XXE blind dan injeksi server-side lain yang tidak terlihat di respons:

```bash
./ssghost666 -url https://app.anda.com -checks xxe
# Listener OOB otomatis dimulai, misal di http://192.168.1.100:54400
```

Jika XML parser target mencoba memuat external entity yang menunjuk ke listener ini, XXE blind terkonfirmasi. Nonaktifkan dengan `-oob-listener=false`.

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
  "last_updated": "2026-01-15",
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

#### JWT Fuzzing Lanjutan

Berikan token Bearer dan aktifkan pemeriksaan `jwt` untuk menguji weak secret, algorithm confusion, dan klaim yang bisa dimanipulasi:

```bash
./ssghost666 -url https://api.anda.com \
  -bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  -checks jwt
```

Modul ini akan mencoba brute-force secret HS256, menurunkan public key dari JWKS/OIDC discovery untuk serangan RS256→HS256, serta menguji eskalasi klaim dan abuse `exp`. Token palsu hanya dilaporkan jika kontrol negatif (token rusak) tetap ditolak target.

#### OAuth / OIDC Flow Testing

```bash
./ssghost666 -url https://app.anda.com -checks oauth
```

Menemukan endpoint authorization dari crawl dan path konvensional, lalu menguji `redirect_uri` bypass, keberadaan PKCE, `state` parameter, dan potensi kebocoran code/token.

#### Session Management Testing

```bash
./ssghost666 -url https://app.anda.com -cookie "session=abc" -checks session
```

Menganalisis cookie sesi yang tertangkap: entropi/prediktabilitas session ID, flag `HttpOnly`/`Secure`/`SameSite`, masa berlaku berlebihan, scope cookie yang terlalu luas, dan indikasi session fixation.

#### SSO / SAML Provider Abuse

```bash
./ssghost666 -url https://app.anda.com -checks sso
```

Modul ini mencari metadata SAML, ACS endpoint, dan JWKS/OIDC discovery dari hasil crawl maupun path konvensional, lalu menguji apakah server **benar-benar memverifikasi** assertion/`kid` — setiap klaim penerimaan dibandingkan dengan kontrol negatif agar server yang menolak dengan benar tidak dilaporkan.

#### Cloud Misconfiguration

```bash
./ssghost666 -url https://app.anda.com -checks cloud
```

Memeriksa file sensitif (`/.git/config`, `/.env`, `/.aws/credentials`, `docker-compose.yml`, dst) dengan validator format per-path, layanan admin tanpa autentikasi (Kubernetes API, Docker API, Consul), Swagger/OpenAPI yang terbuka, cloud metadata endpoint (AWS/GCP/Azure/Alibaba, sebagai bukti SSRF ke IMDS), dan S3 bucket publik dari nama bucket yang ditemukan saat crawl.

#### Subdomain Takeover

```bash
./ssghost666 -url https://app.anda.com -checks subdomain
```

Menelusuri CNAME setiap hostname yang ditemukan (maksimum 40 host, 8 hop per rantai) dan mencocokkannya ke tabel 31 penyedia. **CNAME menggantung saja tidak dilaporkan** — temuan hanya dibuat bila halaman error spesifik penyedia benar-benar terlihat. Pemeriksaannya read-only: SSGhost666 tidak pernah mencoba mengklaim resource.

#### SSL/TLS Testing

```bash
./ssghost666 -url https://app.anda.com -checks tls
```

Memeriksa versi protokol lama (SSLv3, TLS 1.0, TLS 1.1) dengan ClientHello mentah, cipher suite rusak (NULL, EXPORT, RC4, DES, 3DES) yang ditawarkan satu per satu, serta masalah certificate (kedaluwarsa, nama tidak cocok, chain tidak tepercaya, MD5/SHA-1, kunci lemah). Untuk target dengan certificate self-signed selama pengujian internal, gunakan `-insecure` agar temuan "chain tidak tepercaya" tidak dianggap kebisingan. **Heartbleed tidak diuji** karena konfirmasinya bersifat destruktif.

#### Export ke JSON / CSV / SARIF

```bash
# Format ditentukan otomatis dari ekstensi file
./ssghost666 -url https://app.anda.com -out hasil.sarif
./ssghost666 -url https://app.anda.com -out hasil.json
./ssghost666 -url https://app.anda.com -out hasil.csv

# Atau paksa formatnya
./ssghost666 -url https://app.anda.com -out laporan.txt -out-format sarif
```

- `auto` (bawaan) mengenali `.json`, `.csv`, `.sarif` / `.sarif.json`, dan `.html`; ekstensi tak dikenal jatuh kembali ke HTML.
- `sarif` menghasilkan SARIF 2.1.0 yang langsung bisa di-upload ke GitHub code scanning, Azure DevOps, DefectDojo, atau Faraday.
- Redaksi `Authorization`/`Cookie` berlaku juga untuk JSON/CSV/SARIF (matikan dengan `-no-redact`).

#### Adaptive Rate Limiting, Smart Crawling, dan Resume

Ketiganya aktif secara default dan bisa dikombinasikan untuk scan jangka panjang yang sopan terhadap server target:

```bash
./ssghost666 -url https://app.anda.com \
  -rate 20 \
  -smart-crawl \
  -adaptive-rate \
  -resume ~/.ssghost666/scan-state.json
```

- `-adaptive-rate` menurunkan rate otomatis saat target melambat/error, lalu memulihkannya saat normal.
- `-smart-crawl` mengikuti pagination (`?page=`, `?offset=`, dst) dan melewati konten duplikat.
- `-resume <file>` menyimpan & memuat state scan sehingga bisa di-pause (Ctrl-C) dan dilanjutkan nanti.

Nonaktifkan yang tidak diperlukan dengan `-adaptive-rate=false`, `-smart-crawl=false`, atau `-mutate-payload=false`.

## Arsitektur singkat

```
main.go                     — merangkai semua fase
internal/options             — parsing flag CLI
internal/httpclient          — klien HTTP (proxy, auth, TLS, evidence mentah)
internal/ratelimiter         — rate limit + concurrency bersama (+ adaptive)
internal/crawlstate          — state scan (visited + hash konten) untuk resume & dedup
internal/browser             — peluncur tab headless Chrome bersama (dipakai crawler & scanner)
internal/crawler             — crawl statis, ekstraksi JS, discovery (+ kalibrasi soft-404), js-render (chromedp), smart crawl/pagination
internal/openapi             — parser OpenAPI 3 / Swagger 2 → target, termasuk resolver $ref/allOf
internal/scanner             — setiap modul pemeriksaan + engine orkestrasi
  sqli.go                      error-based, boolean-based, time-based
  xss.go + xss_confirm.go      deteksi refleksi + konfirmasi eksekusi browser
  cmdi.go, ssrf.go, auth.go    command injection, SSRF, CORS/broken-access/JWT
  jwt_fuzz.go                  weak HS256 secret, alg confusion, klaim/exp abuse
  oauth.go                     OAuth/OIDC redirect_uri bypass, PKCE, state
  sso_abuse.go                 SAML/JWKS provider abuse (unsigned assertion, kid injection)
  cloud_misconfig.go           file sensitif, K8s/Docker/Consul, IMDS, S3 bucket publik
  subdomain.go                 dangling CNAME + verifikasi halaman error penyedia
  tls.go                       versi protokol lama, cipher lemah, certificate (ClientHello mentah)
  session.go                   session ID/flag/lifetime/scope + fixation
  payload_mutation.go          deteksi WAF + mutasi payload (encoding/obfuscation)
  ssti.go                      template injection (aritmatika + fingerprint engine)
  xxe.go + oob.go              XML external entity + listener callback OOB
  deserialization.go           signature serialized object + konfirmasi sleep
  graphql.go                   deteksi endpoint, introspection, injeksi
  websocket.go                 klien RFC 6455: auth, Origin/CSWSH, injection, rate limit
  blindxss.go                  blind/stored XSS + listener callback beacon
  request_extra.go             helper request raw body (XML/JSON/serialized)
  passive.go + jslibs.go       header/error/listing pasif + versi pustaka JS rentan
internal/report               — output terminal, laporan HTML, dan exporter JSON/CSV/SARIF (export.go)
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
- **Cloud misconfig, subdomain takeover, dan TLS bersifat "bukti, bukan klaim".**
  Pemeriksaan cloud hanya melaporkan file/layanan yang **responsnya lolos
  validator format** (jadi halaman catch-all tidak membanjiri hasil), subdomain
  takeover hanya dilaporkan bila **halaman error spesifik penyedia** benar-benar
  terlihat (CNAME menggantung saja tidak cukup), dan pemeriksaan TLS memakai
  handshake mentah sehingga hasilnya adalah apa yang benar-benar dinegosiasikan
  server. **Heartbleed tidak diuji** karena konfirmasinya butuh mengirim
  heartbeat cacat dan membaca memori target — SSGhost666 tidak melakukan itu.
  Subdomain takeover juga **read-only**: alat tidak pernah mengklaim resource,
  jadi temuan berarti "nama ini bisa diklaim", bukan "nama ini sudah diklaim".
- **Pemeriksaan TLS dan subdomain bekerja di level jaringan**, bukan lewat
  proxy HTTP. Jika Anda merutekan trafik lewat `-proxy`, probe TLS/ClientHello
  dan resolusi DNS tetap keluar langsung dari mesin Anda.
- **Cloud metadata endpoint diuji per-origin** dan hanya dianggap temuan bila
  respons punya penanda khas layanan tersebut (AWS/GCP/Azure/Alibaba). Web
  server biasa yang kebetulan membalas `169.254.169.254` tidak akan dilaporkan.
- Brute-force discovery memakai wordlist bawaan yang sengaja kecil.
  Untuk cakupan lebih luas, arahkan `-wordlist` ke daftar yang lebih
  besar (mis. dari SecLists).

### Fitur yang Sudah Diimplementasikan

Fitur-fitur berikut yang sebelumnya direncanakan **sudah selesai diimplementasikan**:

1. **SSRF in-band dengan listener callback lokal** — SSGhost666 kini menjalankan server HTTP lokal otomatis untuk menerima callback SSRF langsung dari target, sempurna untuk pentest jaringan internal.
2. **DOM-based XSS detection** — deteksi penuh sink berbahaya JavaScript (`innerHTML`, `eval`, `document.write`, dst) yang dipicu dari sumber DOM (`location.hash`, `postMessage`) dengan konfirmasi eksekusi via headless Chrome.
3. **Autentikasi multi-langkah** — framework lengkap untuk alur login kompleks dengan ekstraksi token CSRF, session cookies, dan dukungan JavaScript via headless browser.
4. **Basis data pustaka JS yang updatable** — database CVE kini bisa diperluas dengan file JSON eksternal tanpa rebuild, mendukung update terbaru dan pustaka proprietary.
5. **Blind (stored) XSS dengan storage callback** — beacon ber-marker disuntik ke parameter yang cenderung disimpan, dan listener callback lokal mencatat eksekusi tertunda dari browser korban (cookie, URL, referer, HTML) dengan sweep akhir untuk callback yang telat.
6. **SSTI (Server-Side Template Injection)** — deteksi aritmatika lintas-engine, lalu konfirmasi engine spesifik (Jinja2, Twig, Freemarker, Velocity, ERB, Smarty) plus pencocokan signature error.
7. **XXE (XML External Entity)** — file-read non-destruktif (`/etc/passwd`, `win.ini`) dan konfirmasi blind lewat listener callback OOB lokal.
8. **Insecure deserialization** — signature serialized object (Java, PHP, .NET, pickle) di parameter/header, deteksi error deserialization, dan konfirmasi eksekusi kode via payload pickle `sleep`.
9. **GraphQL introspection & injection** — deteksi endpoint (crawl + path konvensional), introspection schema, authorization bypass, SQLi resolver, dan information disclosure.
10. **WebSocket security testing** — pengumpulan endpoint dari JS statis maupun event browser, lalu uji authentication bypass, Origin/CSWSH, message injection, dan rate limiting dengan klien RFC 6455 minimal.

11. **Advanced SSRF dengan protokol non-HTTP** — dukungan `gopher://` untuk Redis/Memcached, `dict://` untuk service fingerprinting, dan `file://` untuk file system access, dengan konfirmasi via marker matching dan callback listener.
12. **Prototype pollution detection** — deteksi `__proto__`/`constructor.prototype` pollution di JavaScript apps dengan multiple confirmation signals (reflection, error signatures, behavioral changes, timing anomalies).
13. **REST API mass assignment** — inject 20+ protected fields (role, isAdmin, price, balance, isVerified) ke JSON/form requests untuk menemukan field yang seharusnya read-only tapi dapat dimodifikasi.
14. **Rate limiting & resource exhaustion** — burst testing (25 request untuk GET/HEAD/OPTIONS, 12 untuk POST/PUT/PATCH, **tanpa** DELETE agar tidak destruktif) memakai body baseline yang sama untuk mendeteksi missing/weak rate limiting, khususnya pada expensive operations (upload, report, search).
15. **API versioning issues** — scan v0-v5 untuk menemukan legacy versions yang masih aktif dengan inconsistent security headers, missing deprecation warnings, dan potensi unpatched vulnerabilities.
16. **Mutasi payload otomatis** — payload yang ditolak WAF/filter otomatis diulang dalam beberapa varian encoding/obfuscation (case variation, SQL comment whitespace, full/double URL-encoding, HTML hex entities, unicode escapes); varian pertama yang lolos dipakai untuk deteksi, dan temuan mencatat varian yang dicoba.
17. **JWT fuzzing lanjutan** — brute-force weak HS256 secret (~130 kandidat), algorithm confusion RS256→HS256 via JWKS/OIDC discovery, klaim escalation, dan abuse `exp`/`iss`/`aud`, dengan kontrol negatif agar server yang menerima semua token tidak menghasilkan false positive.
18. **OAuth/OIDC flow testing** — deteksi endpoint authorization, 10 varian `redirect_uri` bypass, PKCE missing, `state` parameter abuse, dan kebocoran code/token.
19. **Session management testing** — entropi/prediktabilitas session ID, flag cookie (`HttpOnly`/`Secure`/`SameSite`), masa berlaku berlebihan, scope cookie terlalu luas, dan indikasi session fixation.
20. **Adaptive rate limiting** — rate diturunkan otomatis saat target melambat/error (hingga 1/5 rate awal) dan dipulihkan saat sehat (maksimum 2x rate awal), berbasis baseline latensi bergerak (EWMA).
21. **Smart crawling** — deteksi pola pagination numerik umum (`?page=`, `?offset=`, `?start=`, `?skip=`, dst) untuk mengantre halaman berikutnya (dibatasi 5 URL per halaman), plus suppression konten duplikat berbasis hash respons (sha256).
22. **Resume capability** — state scan (URL dikunjungi + hash konten) disimpan ke file JSON secara atomik dan dimuat ulang, sehingga scan panjang bisa di-pause dan dilanjutkan tanpa mengulang crawl.
23. **SSO/OAuth provider abuse lanjutan** — deteksi metadata SAML / ACS / JWKS / OIDC discovery, pengujian SAML response manipulation (unsigned, signature dirusak, `ds:Signature` kosong) dengan kontrol negatif, RelayState open redirect, JWKS yang membocorkan `kty: oct`, dan `kid` header injection (path traversal + SQL error).
24. **Cloud misconfiguration scanner** — file sensitif dengan validator format per-path, layanan admin tanpa autentikasi (Kubernetes API, Docker API, Consul), Swagger/OpenAPI terbuka, cloud metadata endpoint (AWS/GCP/Azure/Alibaba), dan S3 bucket publik.
25. **Subdomain takeover** — penelusuran rantai CNAME (anti-loop, 8 hop) terhadap tabel 31 penyedia, dengan verifikasi halaman error spesifik penyedia sehingga CNAME menggantung saja tidak dilaporkan. Read-only: tidak pernah mencoba mengklaim resource.
26. **SSL/TLS testing** — deteksi SSLv3/TLS 1.0/1.1 lewat ClientHello mentah, enumerasi cipher suite lemah (NULL/EXPORT/RC4/DES/3DES) satu per satu, dan analisis certificate (kedaluwarsa, nama tidak cocok, chain tidak tepercaya, MD5/SHA-1, kunci lemah). Heartbleed sengaja tidak diuji karena konfirmasinya destruktif.
27. **Export ke format standar** — exporter JSON, CSV (RFC 4180), dan SARIF 2.1.0 dengan pemetaan severity→level, fingerprint per temuan, dan deteksi format otomatis dari ekstensi `-out`.

Setiap fitur sudah diuji production-ready: boolean-blind dan time-based SQLi divalidasi hingga terbukti saling tidak kontaminasi silang, konfirmasi XSS divalidasi dengan Chrome sungguhan hingga benar-benar mengeksekusi script yang disuntik, deteksi pustaka JS diuji dengan 11 skenario, resolver OpenAPI diuji dengan dokumen yang memakai `$ref` bersarang di dalam `allOf`, dan fitur API security baru divalidasi dengan skenario real-world (mass assignment detection tested dengan 23 protected fields, rate limiting dengan concurrent burst testing, API versioning dengan multi-version detection logic). Exporter output juga divalidasi struktural: JSON/CSV di-parse ulang dan SARIF 2.1.0 dicek memiliki `$schema`, `version`, `tool.driver`, `invocations`, `rules`, serta `partialFingerprints` yang konsisten antar-run.

### Roadmap Pengembangan Selanjutnya

Arah perluasan yang masih masuk akal untuk meningkatkan kemampuan SSGhost666:

#### Smart Fuzzing & AI

- **Context-aware fuzzing** — analisis parameter berdasarkan nama/tipe untuk memilih payload yang lebih relevan (parameter `email` → email injection payloads, `id` → IDOR/SQLi numeric, `file` → path traversal).

- **Machine learning untuk false positive reduction** — model ML yang belajar dari historical scan results untuk membedakan true positive vs false positive berdasarkan response patterns, mengurangi manual verification.

#### Reporting & Integration

- **Diff mode untuk CI/CD** — bandingkan hasil scan dengan baseline sebelumnya, laporkan hanya temuan baru untuk integrasi dengan pipeline CI/CD tanpa noise.

- **Slack/Discord/Telegram notification** — kirim alert real-time saat menemukan critical/high findings, dengan summary singkat dan link ke full report.

- **Collaborative scanning** — multiple scanner instances bisa koordinasi lewat shared queue (Redis/RabbitMQ) untuk scan target besar secara distributed, dengan deduplication otomatis.

### Kontribusi yang Diharapkan

Jika Anda ingin berkontribusi, prioritas tertinggi adalah:

1. **Testing & bug reports** — uji di berbagai aplikasi web nyata, laporkan false positives/negatives
2. **Payload database** — tambahkan CVE terbaru ke `jslibs-db`, atau payload bypass untuk WAF populer
3. **Documentation** — tutorial lengkap, video walkthrough, atau case study penggunaan di pentest nyata
4. **Platform support** — port ke Windows/macOS jika ada yang butuh, atau Docker image untuk portability

Pull requests untuk fitur di roadmap sangat diterima — pastikan include test cases dan documentation!

Lisensi: MIT Gagaltotal666 - GhostGTR666.