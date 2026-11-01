<div align="center">

# MACan

[English](README.md) · **Bahasa Indonesia**

**MAC authentication untuk UniFi lewat RADIUS, tanpa 802.1X dan tanpa captive portal.**

Daftarkan MAC address perangkat, tentukan boleh atau tidak per SSID, lalu biarkan UniFi menanyakannya ke MACan setiap kali perangkat mencoba tersambung.

[![FreeRADIUS](https://img.shields.io/badge/FreeRADIUS-3.2-004488)](https://freeradius.org)
[![MariaDB](https://img.shields.io/badge/MariaDB-11-003545?logo=mariadb&logoColor=white)](https://mariadb.org)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-ready-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

## Daftar isi

- [Kenapa MACan](#kenapa-macan)
- [Tampilan](#tampilan)
- [Mulai cepat](#mulai-cepat)
- [Update](#update)
- [Menyambungkan UniFi](#menyambungkan-unifi)
- [Cara keputusan diambil](#cara-keputusan-diambil)
- [Fitur](#fitur)
- [Integrasi UniFi API](#integrasi-unifi-api)
- [Keamanan](#keamanan)
- [Susunan proyek](#susunan-proyek)
- [Pengembangan](#pengembangan)
- [Lisensi](#lisensi)

## Kenapa MACan

UniFi mendukung RADIUS MAC authentication, tetapi tidak menyediakan tempat untuk mengelola daftar MAC-nya. MACan mengisi bagian itu dengan satu panel web untuk mengatur MAC, SSID, dan controller, ditambah jejak audit untuk setiap keputusan autentikasi.

- Perangkat yang tidak mendukung 802.1X, seperti IoT, printer, mesin absensi, dan CCTV, tetap bisa diautentikasi tanpa sertifikat atau supplicant.
- Aturan berlaku per SSID. MAC yang sama boleh diizinkan di `Office-WiFi` dan diblokir di `Guest-WiFi`.
- Sistem bersifat fail-closed. Controller tak dikenal, SSID yang belum diaktifkan, atau mode maintenance yang aktif selalu berujung penolakan.
- Accept dan reject sama-sama dicatat beserta alasannya, sehingga setiap keputusan bisa ditelusuri.

## Tampilan

Panel tersedia dalam tema gelap dan terang, dengan sidebar yang menampilkan jumlah approval, kartu statistik yang bisa diklik ke halaman berfilter, dan grafik accept/reject 24 jam.

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│  MAC  MACan      │  Dashboard                              ☾  admin@local   │
│  MAC Auth UniFi  ├──────────────────────────────────────────────────────────┤
│                  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  RINGKASAN       │  │ Online   │ │ Approval │ │ MAC Rule │ │ Accept   │     │
│  ▸ Dashboard     │  │    24    │ │    3  ▲  │ │   142    │ │  1.204   │     │
│                  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘     │
│  AKSES           │                                                          │
│  ▸ MAC Rules     │  Aktivitas 24 jam                                        │
│  ▸ Approval  (3) │   ▁▂▅█▆▃▂▁▁▂▄▆█▇▅▃▂▁▁▂▃▅▆▄   ■ accept  ■ reject          │
│  ▸ SSID / Grup   │                                                          │
│  ▸ Controller    │  Reject terakhir                                         │
│                  │  aa:bb:cc:dd:ee:ff  Office-WiFi  rule tidak ditemukan    │
│  PEMANTAUAN      │  11:22:33:44:55:66  Guest-WiFi   rule deny               │
│  ▸ Sesi Online   │                                                          │
│  ▸ Auth Log      │                                                          │
│  ▸ Audit Log     │                                                          │
│                  │                                                          │
│  SISTEM          │                                                          │
│  ▸ Admin         │                                                          │
│  ▸ Pengaturan    │                                                          │
│  ▸ Backup        │                                                          │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

## Mulai cepat

Hanya butuh Docker dan Docker Compose. Node dan MariaDB tidak perlu dipasang di host.

```bash
git clone https://github.com/torpedoliar/MACAN.git
cd MACAN
./setup.sh
```

`setup.sh` memeriksa Docker, lalu menjalankan wizard empat langkah:

1. Database: `DB_PASSWORD` dan `DB_ROOT_PASSWORD` dibuat acak tanpa ditanyakan, karena hanya dipakai antar container.
2. Kunci sesi: `SESSION_SECRET` dibuat acak (32 byte).
3. Admin pertama: email dan password diminta. Password diketik dua kali, tidak ditampilkan, minimal 8 karakter.
4. Akses panel: pertanyaan "Pakai HTTPS?" menentukan `COOKIE_SECURE`. Default `n`, aman untuk HTTP biasa.

Setelah itu `.env` ditulis dengan permission `600`, compose dibangun, dan skrip menunggu panel menjawab sebelum menampilkan URL dan langkah berikutnya.

Skrip aman dijalankan berulang. Nilai yang sudah terisi tidak ditanyakan lagi dan tidak ditimpa; wizard hanya menanyakan yang masih kosong. Tanpa terminal (misalnya lewat pipe atau CI), skrip tetap membuat ketiga rahasia, lalu berhenti dan menyebutkan nilai mana yang harus diisi manual.

<details>
<summary>Setup manual</summary>

```bash
cp .env.example .env
# sunting .env, isi semua nilai "change-..."
docker compose up -d --build
```

| Variabel | Isi |
|---|---|
| `DB_PASSWORD` | password user database `macan` |
| `DB_ROOT_PASSWORD` | password root MariaDB |
| `SESSION_SECRET` | string acak panjang, misalnya hasil `openssl rand -hex 32` |
| `ADMIN_EMAIL` | email login admin pertama |
| `ADMIN_PASSWORD` | password admin pertama |
| `COOKIE_SECURE` | `0` untuk HTTP, `1` hanya bila berada di belakang HTTPS |

Docker Compose menginterpolasi isi `.env`, jadi tanda `$` di dalam password harus ditulis `$$`. Tanpa itu, `Pa$word` sampai ke container sebagai `Pa`. `setup.sh` melakukan escape ini secara otomatis.

</details>

Buka `http://<ip-server>:880` dan login dengan `ADMIN_EMAIL` / `ADMIN_PASSWORD`. Skema database dan admin pertama dibuat otomatis saat boot pertama.

| Port | Protokol | Fungsi |
|---|---|---|
| `880` | tcp | panel web |
| `1812` | udp | RADIUS authentication |
| `1813` | udp | RADIUS accounting |

> `COOKIE_SECURE=1` di atas HTTP biasa membuat cookie sesi tidak pernah terkirim, sehingga login gagal tanpa pesan error. Biarkan `0` sampai HTTPS benar-benar aktif.

`GET /health` (tanpa login) menjawab `{"status":"ok"}` bila database terjangkau dan `503` bila tidak. Endpoint ini dipakai `setup.sh` dan cocok untuk monitoring uptime.

### Lupa password admin

```bash
bash reset-admin-password.sh
```

Skrip meminta email admin, membaca kredensial database dari `.env`, lalu mengatur ulang password akun tersebut ke password default yang tertulis di skrip. Karena nilai default itu ada di repositori, segera ganti password setelah login. Nama container database bisa diubah lewat variabel `CONTAINER`.

## Update

```bash
./update.sh
```

Lima langkah, berhenti di langkah pertama yang gagal:

1. Backup database ke `backups/macan_<tanggal>.sql` lewat `mariadb-dump --single-transaction`. Backup konsisten tanpa mengunci tabel, jadi RADIUS tetap menjawab selama backup. Bila backup gagal, update dibatalkan dan tidak ada yang berubah.
2. `git pull --ff-only origin main`. Bila gagal karena perubahan lokal, container masih versi lama dan tidak ada yang rusak.
3. Build image `web` dan `radius`. Image `radius` wajib ikut karena file konfigurasinya di-`COPY` ke dalam image; restart saja tidak memuat perubahan.
4. Recreate container `web` dan `radius` dengan `--no-deps`.
5. Tunggu `/health` menjawab 200. Migrasi berjalan saat `web` start, jadi langkah ini sekaligus membuktikan skema sudah sinkron.

Container `db` tidak pernah di-stop, di-rebuild, atau dihapus. Perintah `down` dan `down -v` tidak pernah dipanggil, sehingga volume `db_data` tidak tersentuh. Sepuluh backup terbaru disimpan, sisanya dihapus.

Kembali ke data sebelum update:

```bash
docker exec -i $(docker compose ps --format '{{.Name}}' db) \
  sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" macan' \
  < backups/macan_<tanggal>.sql
```

> Isi `backups/` memuat shared secret RADIUS, kredensial UniFi, dan token Telegram. Folder ini ada di `.gitignore`; jangan salin ke tempat dengan izin akses yang lebih longgar.

## Menyambungkan UniFi

### 1. Tambahkan controller di MACan

Buka menu Controller → Tambah, lalu isi nama, IP sumber paket RADIUS, dan shared secret.

Pengirim paket RADIUS belum tentu controller-nya. Pada UniFi, AP biasanya menghubungi RADIUS secara langsung, jadi IP sumbernya adalah IP AP, bukan IP controller. Karena itu kolom IP menerima dua bentuk:

| Isi | Kapan dipakai |
|---|---|
| `10.10.0.100` | hanya satu host yang mengirim (misalnya controller yang me-relay RADIUS) |
| `10.10.0.0/24` | semua AP di satu subnet mengirim langsung |

Baris host lebih diutamakan daripada baris subnet yang memuatnya, jadi satu AP bisa diberi entri sendiri tanpa mengganggu entri subnet. Prefix yang diterima `/8` sampai `/32`. Shared secret berlaku untuk seluruh subnet yang didaftarkan, jadi pilih subnet sesempit mungkin.

Perubahan controller tidak butuh restart. FreeRADIUS mencari IP sumber yang belum dikenal di tabel `controllers` per paket (`radius/macan_clients.conf`) dan menyimpan hasilnya selama 5 menit. Controller baru langsung dikenali pada paket pertama, sedangkan perubahan IP, shared secret, penonaktifan, atau penghapusan berlaku paling lama 5 menit. Untuk menghapus cache seketika, jalankan dari dalam container radius: `radmin -e "del client ipaddr <ip>"`.

### 2. Buat RADIUS profile di UniFi

Settings → Profiles → RADIUS → Create New:

| Field | Nilai |
|---|---|
| Auth Server | IP server MACan |
| Auth Port | `1812` |
| Auth Secret | shared secret yang sama dengan di MACan |
| Accounting Server | IP server MACan |
| Accounting Port | `1813` |
| Accounting | aktifkan |

### 3. Aktifkan MAC authentication di WiFi

Settings → WiFi → \<SSID\> → Advanced → MAC Authentication, lalu pilih RADIUS profile tadi.

### 4. Aktifkan SSID di MACan

Paket pertama dari UniFi membuat SSID muncul otomatis di menu SSID dengan status nonaktif. Ini disengaja: operator harus mengaktifkannya sebelum ada MAC yang bisa lolos.

## Cara keputusan diambil

Setiap Access-Request dievaluasi berurutan dan berhenti di kecocokan pertama.

```
Access-Request
      │
      ├─ Calling-Station-Id bukan 12 hex?           → REJECT  MAC tidak valid
      ├─ IP pengirim tak ada di controllers?        → REJECT  controller tak dikenal
      ├─ maintenance_mode = 1?                      → REJECT  mode maintenance
      ├─ SSID belum diaktifkan operator?            → REJECT  SSID nonaktif
      │
      └─ cari rule (scope controller dulu, lalu global)
              ├─ allow     → ACCEPT
              ├─ deny      → REJECT  rule deny
              ├─ disabled  → REJECT  rule disabled
              └─ tak ada   → REJECT  rule tidak ditemukan  ← muncul di Approval
```

MAC dinormalisasi lebih dulu, jadi keempat format ini dianggap sama:

```
aa:bb:cc:dd:ee:ff    aabbccddeeff    aa-bb-cc-dd-ee-ff    aabb.ccdd.eeff
```

Rule bisa bersifat global (berlaku di semua controller) atau per controller. Bila keduanya cocok, rule per controller yang menang.

## Fitur

### Akses

- MAC Rules: CRUD dengan status `allow`, `deny`, atau `disabled`, plus kolom pemilik, nama perangkat, hostname, dan catatan. Pencarian menerima MAC dengan atau tanpa titik dua. Halaman dikelompokkan per SSID; rule allow tampil terbuka, sedangkan deny dan nonaktif dilipat. Form rule baru dan edit menyediakan dropdown SSID dari inventaris.
- Approval: MAC yang ditolak karena belum punya rule dikumpulkan di satu halaman, dikelompokkan per SSID, dengan pencarian dan paginasi. Satu klik mengubahnya menjadi rule allow. Halaman ini dihitung dari tidak adanya rule, bukan dari teks alasan reject, jadi tidak rusak bila pesan kebijakan berubah.
- SSID: SSID yang belum dikenal muncul otomatis saat paket pertama masuk, dengan status nonaktif.
- Grup SSID: beberapa SSID bisa digabung dalam satu grup, lalu satu rule grup diterapkan ke semua anggotanya. Rule grup disimpan sebagai satu baris `mac_rules` per anggota, sehingga lookup FreeRADIUS tetap satu `SELECT` per pasangan MAC dan SSID. Grup bisa diganti nama dan anggotanya diubah; rule anggota disinkronkan ulang secara otomatis.
- Controller: daftar NAS beserta shared secret, IP host atau subnet, dan kredensial UniFi opsional. Sistem menolak IP duplikat dan menolak penghapusan controller yang masih dipakai SSID, rule, atau log.
- Multi-CloudKey: halaman Rules, Approval, dan Sesi bisa difilter per controller, sehingga satu instalasi MACan dapat melayani beberapa CloudKey atau UDM.

### Pemantauan

- Sesi Online: dibangun dari paket accounting, lengkap dengan informasi siapa yang terhubung. Nama pemilik dan nama perangkat diambil dari rule MAC yang cocok (scope controller didahulukan dari global, sama seperti `default.conf`). Sesi tanpa rule ditandai `tanpa rule`. `Accounting-On`/`Off` dari controller yang reboot menutup semua sesinya, dan sesi tanpa update melewati batas waktu ditandai selesai oleh cron.
- Auth Log: accept dan reject beserta alasan, bisa difilter, ditambah atribut mentah paket dalam JSON.
- Audit Log: mencatat siapa mengubah apa dan kapan. Nilai rahasia seperti token bot tidak pernah ditulis ke sini.
- Vendor perangkat: tabel OUI IEEE (sekitar 35 ribu prefix) diunduh dari mirror `linuxnet.ca` dan diperbarui otomatis setiap tanggal 1 pukul 03.07, sehingga panel bisa menampilkan vendor dari setiap MAC.

### Otomasi

- Audit inaktif: rule `allow` yang tidak pernah tersambung selama `inactive_after_days` (default 90, bisa diubah di Pengaturan) otomatis diubah menjadi `deny` dan ditandai Inactive. Penanda ini kolom terpisah (`inactive_since`), bukan status keempat, karena FreeRADIUS hanya mengenal `allow`/`deny`/`disabled`; nilai lain akan dibaca sebagai "rule tidak ditemukan" dan MAC-nya muncul lagi di Approval. Sweep memakai dua waktu sekaligus, yaitu koneksi terakhir dan edit admin terakhir, supaya rule yang baru di-allow ulang tidak langsung dibalik pada putaran berikutnya. Filter Inactive tersedia di halaman MAC Rules.
- Notifikasi: Telegram dan/atau webhook generik untuk lonjakan reject dari satu MAC, SSID baru terdeteksi, dan MAC yang menunggu approval. Dedupe berbasis waktu mencegah banjir pesan.
- Pembersihan otomatis: cron tiap jam (menit ke-7) memangkas log yang melewati masa simpan, menutup sesi basi, menjalankan sweep inaktif, dan mengirim notifikasi yang tertunda.

### Sistem

- Admin: akun per orang dengan login masing-masing. Menonaktifkan tanda Aktif langsung memblokir login tanpa menghapus riwayat. Akun juga bisa dihapus; baris Audit Log miliknya tetap ada sebagai "deleted admin". Ada dua pengaman: admin tidak bisa menghapus atau menonaktifkan akunnya sendiri, dan admin aktif terakhir tidak bisa dihapus atau dinonaktifkan.
- Import/Export CSV dengan kolom `scope,controller,ssid,mac,status,owner,device,note`. Baris bermasalah dilaporkan per nomor baris, baris lain tetap masuk. Contoh file bisa diunduh dari halaman MAC Rules.
- Backup & Restore: unduh seluruh data sebagai JSON. Restore berjalan tiga langkah, yaitu unggah, pratinjau isi, lalu konfirmasi dengan mengetik `GANTI`. Backup dari instalasi lain ditolak.
- Mode Maintenance: sekali klik, semua autentikasi baru ditolak dan panel menolak perubahan data dengan HTTP 503. Sesi yang sudah berjalan tidak terpengaruh karena tidak melakukan re-auth.
- Halaman About berisi informasi pengembang dan URL repositori.

## Integrasi UniFi API

Setiap controller bisa diberi kredensial UniFi agar MACan mengambil hostname perangkat dari UniFi Network:

- `unifi_host`, `unifi_site`, dan `unifi_api_key` untuk UniFi Network Integration API (`/proxy/network/integration/v1`, header `X-API-KEY`). Sertifikat self-signed diterima hanya bila verifikasi TLS dimatikan untuk controller tersebut.
- `unifi_username` dan `unifi_password` untuk classic API. MACan mencoba jalur login UDM (`/api/auth/login`) dan CloudKey (`/api/login`), sehingga hostname client yang sedang offline pun ikut tersinkron.
- Tombol Cek koneksi menguji login classic API dengan user dan password yang diisi.
- Hostname semua client UniFi ikut disinkronkan, lalu ditampilkan di kolom Hostname pada halaman Rules dan Approval. Pengambilan data mengikuti batas halaman server UniFi (200 client per halaman).

## Keamanan

- Password admin di-hash dengan bcrypt. Tidak ada password yang tersimpan sebagai teks.
- Sesi disimpan di database, bukan di memori, jadi restart tidak membuat semua orang logout.
- Setiap form memakai CSRF token. Route unggah memverifikasinya setelah multer selesai mem-parsing body, dan `self-check` punya assertion yang menggagalkan build bila route unggah baru lupa melakukannya.
- Semua query memakai parameter binding; tidak ada SQL yang disusun dari string.
- Token notifikasi tidak pernah dikirim balik ke halaman dan tidak pernah masuk audit log.
- `.env` ada di `.gitignore`. Ganti semua nilai default sebelum dipakai di jaringan produksi.

> Shared secret RADIUS melewati jaringan dalam bentuk yang lemah secara kriptografis. Jalankan MACan di VLAN manajemen, bukan di jaringan yang bisa diakses client WiFi. Untuk akses panel dari luar, letakkan di belakang reverse proxy HTTPS lalu set `COOKIE_SECURE=1`.

## Susunan proyek

```
compose.yaml              tiga service: db, web, radius
setup.sh                  bootstrap: cek docker, wizard .env, generate secret, up
update.sh                 update: backup db, git pull, rebuild web+radius, tunggu /health
reset-admin-password.sh   reset password admin lewat container MariaDB
db/schema.sql             skema awal, dijalankan MariaDB saat boot pertama
radius/
  Dockerfile              FreeRADIUS + file config di bawah
  default.conf            kebijakan authorize + accounting (inti keputusan)
  sql.conf                koneksi database, read_clients dari tabel controllers
  queries.conf            query client/NAS
  macan_clients.conf      lookup controller dinamis per paket
web/
  Dockerfile              node:20-alpine
  public/                 app.css (design token, dark mode) dan app.js (vanilla JS)
  src/
    app.js                shell Express: view, middleware, mounting route
    migrate.js            migrasi idempoten, jalan setiap start
    middleware.js         session store MySQL, CSRF, maintenance guard, error handler
    radius-policy.js      normalisasi MAC, dipakai bersama route
    pending.js            definisi "menunggu approval"
    ssid-groups.js        perluasan rule grup ke anggota SSID
    unifi.js              klien UniFi Integration API dan classic API
    oui.js                tabel vendor OUI IEEE
    db.js  auth.js  audit.js  notifications.js  cron.js  logo.js
    routes/               13 route
    views/                template EJS
  test/self-check.js      compile + render semua view, dengan data maupun kosong
```

Arsitekturnya sengaja tipis: tanpa framework frontend, tanpa build step, tanpa ORM. `docker compose up` cukup untuk menjalankan semuanya.

## Pengembangan

```bash
cd web
npm install
npm run self-check     # compile + render semua view, dengan data dan tanpa data
npm start              # butuh MariaDB; lebih mudah lewat compose
```

Config di `radius/` di-`COPY` ke dalam image, jadi setelah mengubahnya restart saja tidak cukup:

```bash
docker compose up -d --build radius
```

Menguji keputusan tanpa perangkat sungguhan:

```bash
docker compose exec radius sh -c 'printf "User-Name=aa:bb:cc:dd:ee:ff\n\
Calling-Station-Id=aa:bb:cc:dd:ee:ff\n\
Called-Station-Id=aa:bb:cc:dd:ee:ff:Office-WiFi\n" \
  | radclient -x 127.0.0.1:1812 auth <shared-secret>'
```

Memeriksa config FreeRADIUS: `docker compose exec radius freeradius -XC`

> Di dalam `radius/default.conf`, kurung kurawal yang tidak berpasangan akan menutup ekspansi `%{sql:...}` lebih awal dan memotong query. Hindari quantifier seperti `{12}` di dalam regex, termasuk di dalam komentar.

## Lisensi

Dirilis di bawah [Lisensi MIT](LICENSE). Hak cipta © 2026 torpedoliar.

Dikembangkan oleh Yohanes Octavian Rizky ([@torpedoliar](https://github.com/torpedoliar)).
