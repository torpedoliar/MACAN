<div align="center">

# MACan

**MAC Authentication untuk UniFi — RADIUS, tanpa 802.1X, tanpa portal.**

Daftarkan MAC address perangkat, tentukan boleh atau tidak per SSID, dan biarkan
UniFi menanyakannya ke MACan setiap kali perangkat mencoba tersambung.

[![FreeRADIUS](https://img.shields.io/badge/FreeRADIUS-3.2-004488?logo=freebsd&logoColor=white)](https://freeradius.org)
[![MariaDB](https://img.shields.io/badge/MariaDB-11-003545?logo=mariadb&logoColor=white)](https://mariadb.org)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-ready-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## Kenapa MACan

UniFi bisa memakai RADIUS MAC authentication, tapi tidak menyediakan tempat
untuk mengelola daftar MAC-nya. MACan mengisi bagian itu: satu panel web untuk
mengatur MAC, SSID, dan controller — plus jejak audit dari setiap keputusan
autentikasi.

- **Tanpa sertifikat, tanpa supplicant.** Perangkat IoT, printer, mesin absensi, dan CCTV yang tidak bisa 802.1X tetap bisa diautentikasi.
- **Per SSID, bukan per site.** MAC yang sama boleh diizinkan di `Office-WiFi` dan diblokir di `Guest-WiFi`.
- **Fail-closed.** Controller tak dikenal, SSID belum diaktifkan, atau mode maintenance aktif → tolak. Tidak pernah "izinkan karena ragu".
- **Setiap keputusan tercatat.** Accept dan reject sama-sama masuk log dengan alasannya, jadi bisa ditelusuri.

---

## Tampilan

Panel gelap/terang, sidebar dengan badge approval, kartu statistik yang bisa
diklik ke halaman berfilter, dan grafik accept/reject 24 jam.

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
│  ▸ SSID          │                                                          │
│  ▸ Controller    │  Reject terakhir                                         │
│                  │  aa:bb:cc:dd:ee:ff  Office-WiFi  rule tidak ditemukan    │
│  PEMANTAUAN      │  11:22:33:44:55:66  Guest-WiFi   rule deny               │
│  ▸ Sesi Online   │                                                          │
│  ▸ Auth Log      │                                                          │
│  ▸ Audit Log     │                                                          │
│                  │                                                          │
│  SISTEM          │                                                          │
│  ▸ Pengaturan    │                                                          │
│  ▸ Backup        │                                                          │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

---

## Mulai cepat

Butuh Docker dan Docker Compose. Tidak perlu Node atau MariaDB di host.

```bash
git clone https://github.com/torpedoliar/MACAN.git
cd MACAN
./setup.sh
```

`setup.sh` memeriksa Docker lalu menjalankan **wizard empat langkah**:

1. **Database** — `DB_PASSWORD` dan `DB_ROOT_PASSWORD` digenerate acak. Tidak ditanyakan; password ini hanya dipakai antar container.
2. **Kunci sesi** — `SESSION_SECRET` digenerate acak (32 byte).
3. **Admin pertama** — email dan password diminta. Password diketik dua kali, tidak ditampilkan, minimal 8 karakter.
4. **Akses panel** — "Pakai HTTPS?" menentukan `COOKIE_SECURE`. Default `n`, yaitu aman untuk HTTP plain.

Setelah itu `.env` ditulis dengan permission `600`, compose dibangun, dan skrip
menunggu sampai panel menjawab sebelum menampilkan URL dan langkah berikutnya.

Aman dijalankan berulang: nilai yang sudah terisi tidak ditanyakan lagi dan tidak
ditimpa — wizard hanya menanyakan yang masih kosong. Tanpa terminal (mis. lewat
pipe atau CI) skrip tetap men-generate ketiga rahasia, lalu berhenti dan
menyebutkan nilai mana yang harus diisi manual.

<details>
<summary>Atau setup manual</summary>

```bash
cp .env.example .env
# sunting .env, isi semua nilai "change-..."
docker compose up -d --build
```

| Variabel | Isi |
|---|---|
| `DB_PASSWORD` | password user database `macan` |
| `DB_ROOT_PASSWORD` | password root MariaDB |
| `SESSION_SECRET` | string acak panjang, mis. hasil `openssl rand -hex 32` |
| `ADMIN_EMAIL` | email login admin pertama |
| `ADMIN_PASSWORD` | password admin pertama |
| `COOKIE_SECURE` | `0` untuk HTTP, `1` **hanya** kalau di belakang HTTPS |

Docker Compose menginterpolasi isi `.env`, jadi `$` di dalam password harus
ditulis `$$` — `Pa$word` sampai ke container sebagai `Pa` saja. `setup.sh`
melakukan escape ini sendiri.

</details>

Buka `http://<ip-server>:880` dan login dengan `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
Skema database dan admin pertama dibuat otomatis saat boot pertama.

| Port | Protokol | Fungsi |
|---|---|---|
| `880` | tcp | panel web |
| `1812` | udp | RADIUS authentication |
| `1813` | udp | RADIUS accounting |

> `COOKIE_SECURE=1` di atas HTTP plain membuat cookie sesi tidak pernah terkirim —
> login akan gagal tanpa pesan error. Biarkan `0` sampai HTTPS benar-benar aktif.

---

## Menyambungkan UniFi

**1. Tambahkan controller di MACan.** Menu **Controller → Tambah**. Isi nama,
IP address controller (IP yang dipakai UniFi untuk mengirim paket RADIUS), dan
shared secret.

**2. Buat RADIUS profile di UniFi.** *Settings → Profiles → RADIUS → Create New*:

| Field | Nilai |
|---|---|
| Auth Server | IP server MACan |
| Auth Port | `1812` |
| Auth Secret | shared secret yang sama dengan di MACan |
| Accounting Server | IP server MACan |
| Accounting Port | `1813` |
| Accounting | aktifkan |

**3. Aktifkan MAC authentication di WiFi.** *Settings → WiFi → \<SSID\> →
Advanced → MAC Authentication*, pilih RADIUS profile tadi.

**4. Aktifkan SSID di MACan.** Paket pertama dari UniFi membuat SSID muncul
otomatis di menu **SSID** dengan status **nonaktif** — ini disengaja. Aktifkan
dulu sebelum ada MAC yang bisa lolos.

> Setelah menambah atau mengubah controller, jalankan `docker compose restart radius`.
> FreeRADIUS membaca daftar client sekali saat start, jadi controller baru belum
> dikenali sampai di-restart.

---

## Cara keputusan diambil

Setiap Access-Request dievaluasi berurutan. Berhenti di kecocokan pertama.

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

Rule bisa **global** (berlaku di semua controller) atau **per controller**.
Kalau keduanya cocok, yang per controller menang.

---

## Fitur

**MAC Rules** — CRUD dengan status `allow` / `deny` / `disabled`, kolom pemilik,
nama perangkat, dan catatan. Pencarian menerima MAC dengan atau tanpa titik dua.

**Approval** — MAC yang ditolak karena belum punya rule dikumpulkan di satu
halaman. Satu klik untuk mengubahnya menjadi rule allow. Halaman ini dihitung
dari *ketiadaan rule*, bukan dari teks alasan reject, jadi tidak rusak kalau
pesan kebijakan berubah.

**SSID** — SSID yang belum dikenal muncul otomatis saat paket pertama masuk,
dengan status nonaktif. Operator harus mengaktifkannya secara sadar.

**Controller** — daftar NAS beserta shared secret. Menolak IP duplikat, dan
menolak penghapusan controller yang masih dipakai SSID, rule, atau log.

**Sesi Online** — dibangun dari paket accounting. `Accounting-On`/`Off` dari
controller yang reboot menutup semua sesinya. Sesi tanpa update melebihi batas
waktu ditandai selesai oleh cron.

**Auth Log** — accept dan reject dengan alasan, bisa difilter, plus atribut
mentah paket dalam JSON untuk penelusuran.

**Audit Log** — siapa mengubah apa dan kapan. Nilai rahasia (token bot, dsb.)
tidak pernah ditulis ke sini.

**Notifikasi** — Telegram dan/atau webhook generik untuk: lonjakan reject dari
satu MAC, SSID baru terdeteksi, dan MAC menunggu approval. Ada dedupe berbasis
waktu supaya tidak membanjiri.

**Import/Export CSV** — kolom `scope,controller,ssid,mac,status,owner,device,note`.
Baris yang bermasalah dilaporkan per nomor baris, baris lain tetap masuk. Ada
contoh file yang bisa diunduh dari halaman MAC Rules.

**Backup & Restore** — unduh seluruh data sebagai JSON. Restore berjalan tiga
langkah: unggah → pratinjau isinya → konfirmasi dengan mengetik `GANTI`. Backup
dari instalasi lain ditolak.

**Mode Maintenance** — sekali klik, semua autentikasi baru ditolak dan panel
menolak perubahan data dengan HTTP 503. Sesi yang sudah berjalan tidak
terpengaruh karena tidak melakukan re-auth.

**Pembersihan otomatis** — cron tiap jam (menit ke-7) memangkas log melewati
masa simpan, menutup sesi basi, dan mengirim notifikasi yang tertunda.

---

## Keamanan

- Password admin di-hash dengan **bcrypt**. Tidak ada password tersimpan sebagai teks.
- Sesi disimpan di database (bukan memori), jadi restart tidak melogout semua orang.
- **CSRF token** pada setiap form. Route unggah memverifikasinya setelah multer selesai mem-parsing body — ada assertion di `self-check` yang menggagalkan build kalau route unggah baru lupa melakukannya.
- Semua query memakai **parameter binding**, tidak ada penyusunan SQL dari string.
- Token notifikasi tidak pernah dikirim balik ke halaman dan tidak pernah masuk audit log.
- `.env` masuk `.gitignore`. Ganti **semua** nilai default sebelum dipakai di jaringan sungguhan.

> RADIUS shared secret melewati jaringan dalam bentuk yang lemah secara
> kriptografis. Jalankan MACan di VLAN manajemen, bukan di jaringan yang bisa
> diakses klien WiFi. Untuk akses panel dari luar, taruh di belakang reverse
> proxy HTTPS lalu set `COOKIE_SECURE=1`.

---

## Susunan proyek

```
compose.yaml              tiga service: db, web, radius
setup.sh                  bootstrap: cek docker, wizard .env, generate secret, up
db/schema.sql             skema awal, dijalankan MariaDB saat boot pertama
radius/
  Dockerfile              FreeRADIUS + tiga file config di bawah
  default.conf            kebijakan authorize + accounting (inti keputusan)
  sql.conf                koneksi database, read_clients dari tabel controllers
  queries.conf            query client/NAS
web/
  Dockerfile              node:20-alpine
  public/app.css          448 baris, 56 design token, dark mode, responsif
  public/app.js           69 baris vanilla JS, semuanya progressive enhancement
  src/
    app.js                shell Express: view, middleware, mounting route
    migrate.js            migrasi idempoten, jalan setiap start
    middleware.js         session store MySQL, CSRF, maintenance guard, error handler
    db.js  auth.js  audit.js  notifications.js  cron.js
    pending.js            definisi "menunggu approval"
    radius-policy.js      normalisasi MAC, dipakai bersama route
    routes/               10 route
    views/                18 template EJS
  test/self-check.js      compile + render semua view, isi maupun kosong
```

Arsitektur sengaja tipis: tanpa framework frontend, tanpa build step, tanpa ORM.
`docker compose up` cukup untuk menjalankan semuanya.

---

## Pengembangan

```bash
cd web
npm install
npm run self-check     # compile + render semua view, dengan data dan tanpa data
npm start              # butuh MariaDB; lebih mudah pakai compose
```

Setelah mengubah file di `radius/`, config-nya di-`COPY` ke dalam image — jadi
`restart` saja tidak cukup:

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

> Di dalam `radius/default.conf`, kurung kurawal tak berpasangan akan menutup
> ekspansi `%{sql:...}` lebih awal dan memotong query di tengah. Hindari
> quantifier seperti `{12}` di dalam regex — termasuk di dalam komentar.

---

## Lisensi

MIT
