#!/bin/sh
# Bootstrap MACan: wizard pengisian .env lalu jalankan compose.
# Aman dijalankan ulang — .env yang sudah lengkap tidak disentuh.
#
# ponytail: sh POSIX, tanpa dependensi selain docker. Bukan Python/pip — proyek
# ini nol file .py; npm install sudah dijalankan di dalam web/Dockerfile.
set -eu

cd "$(dirname "$0")"

say() { printf '%s\n' "$*"; }
die() { printf 'gagal: %s\n' "$*" >&2; exit 1; }
rule() { say '------------------------------------------------------------'; }

# --- prasyarat ---------------------------------------------------------------
command -v docker >/dev/null 2>&1 \
  || die 'docker tidak ditemukan. Pasang Docker lebih dulu.'
docker compose version >/dev/null 2>&1 \
  || die 'plugin "docker compose" tidak tersedia (butuh Compose v2).'

say ''
rule
say '  MACan — MAC authentication untuk UniFi'
say '  setup awal'
rule
say "OK  docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo terpasang)"

# Wizard hanya jalan kalau ada terminal. Di CI atau `curl | sh`, jatuh ke mode
# non-interaktif di bagian bawah: secret digenerate, kredensial admin dibiarkan
# placeholder, keluar dengan exit 1 supaya tak ada yang boot dengan nilai contoh.
TTY=0
if [ -r /dev/tty ] && [ -t 1 ]; then
  TTY=1
  trap 'stty echo < /dev/tty 2>/dev/null || true; say ""; exit 130' INT
fi

# --- baca kondisi .env sekarang ---------------------------------------------
[ -f .env.example ] || die '.env.example hilang.'
SRC=.env.example
[ -f .env ] && SRC=.env

# Docker Compose menginterpolasi nilai .env: satu "$" dianggap awal nama
# variabel dan sisa password ikut hilang ("Pa$word" sampai ke container sebagai
# "Pa"). "$$" adalah cara menulis satu "$" literal. esc() dipakai saat menulis,
# get() membalikkannya saat membaca, supaya jalan ulang tidak menggandakan terus.
esc() { printf '%s' "$1" | sed 's/\$/$$/g'; }

# tr -d '\r' karena editor Windows meninggalkan CRLF dan nilainya jadi bawa \r.
get() { sed -n "s/^$1=//p" "$SRC" | head -n 1 | tr -d '\r' | sed 's/\$\$/$/g'; }
placeholder() { case "$1" in ''|change-*) return 0 ;; *) return 1 ;; esac; }

DB_PASSWORD=$(get DB_PASSWORD)
DB_ROOT_PASSWORD=$(get DB_ROOT_PASSWORD)
SESSION_SECRET=$(get SESSION_SECRET)
ADMIN_EMAIL=$(get ADMIN_EMAIL)
ADMIN_PASSWORD=$(get ADMIN_PASSWORD)
COOKIE_SECURE=$(get COOKIE_SECURE)
[ -n "$COOKIE_SECURE" ] || COOKIE_SECURE=0

NEED=''
for k in DB_PASSWORD DB_ROOT_PASSWORD SESSION_SECRET ADMIN_EMAIL ADMIN_PASSWORD; do
  eval "v=\$$k"
  if placeholder "$v"; then NEED="$NEED $k"; fi
done

# --- generator nilai acak ----------------------------------------------------
gen() {
  openssl rand -hex "$1" 2>/dev/null && return 0
  head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n' && return 0
  die 'tidak bisa membuat nilai acak: openssl dan /dev/urandom sama-sama tidak tersedia.'
}

# --- helper input ------------------------------------------------------------
# Semua baca dari /dev/tty, bukan stdin, supaya tetap jalan saat skrip
# dijalankan lewat pipe.
ask() { # ask <prompt> <default>
  _p=$1; _d=$2
  if [ -n "$_d" ]; then printf '%s [%s]: ' "$_p" "$_d" > /dev/tty
  else printf '%s: ' "$_p" > /dev/tty; fi
  IFS= read -r _a < /dev/tty || _a=''
  _a=$(printf '%s' "$_a" | tr -d '\r')
  [ -n "$_a" ] || _a=$_d
  REPLY_VAL=$_a
}

ask_secret() { # ask_secret <prompt>; echo dimatikan selama mengetik
  printf '%s: ' "$1" > /dev/tty
  stty -echo < /dev/tty 2>/dev/null || true
  IFS= read -r _s < /dev/tty || _s=''
  stty echo < /dev/tty 2>/dev/null || true
  printf '\n' > /dev/tty
  REPLY_VAL=$(printf '%s' "$_s" | tr -d '\r')
}

ask_yn() { # ask_yn <prompt> <y|n default>
  while :; do
    ask "$1 (y/n)" "$2"
    case "$REPLY_VAL" in
      y|Y|ya|yes) REPLY_VAL=y; return 0 ;;
      n|N|no|tidak) REPLY_VAL=n; return 0 ;;
      *) say '  jawab y atau n.' ;;
    esac
  done
}

# --- wizard ------------------------------------------------------------------
if [ -n "$NEED" ] && [ "$TTY" = 1 ]; then
  say ''
  say 'Beberapa nilai belum diisi. Wizard akan menanyakannya satu per satu.'
  say 'Tekan Enter untuk memakai nilai dalam [kurung].'
  say ''

  # 1. Password database. Tak pernah diketik manusia, jadi langsung digenerate.
  if placeholder "$DB_PASSWORD" || placeholder "$DB_ROOT_PASSWORD"; then
    rule
    say '1/4  Database'
    say '     Password MariaDB tidak perlu kamu hafal — hanya dipakai antar'
    say '     container. Digenerate acak.'
    placeholder "$DB_PASSWORD" && DB_PASSWORD=$(gen 24)
    placeholder "$DB_ROOT_PASSWORD" && DB_ROOT_PASSWORD=$(gen 24)
    say 'OK   DB_PASSWORD dan DB_ROOT_PASSWORD digenerate (24 byte acak)'
    say ''
  fi

  # 2. Kunci sesi. Sama, tak pernah diketik manusia.
  if placeholder "$SESSION_SECRET"; then
    rule
    say '2/4  Kunci sesi'
    say '     Menandatangani cookie login. Nilai lemah = sesi bisa ditempa.'
    SESSION_SECRET=$(gen 32)
    say 'OK   SESSION_SECRET digenerate (32 byte acak)'
    say ''
  fi

  # 3. Kredensial admin. Ini yang benar-benar butuh manusia.
  if placeholder "$ADMIN_EMAIL"; then
    rule
    say '3/4  Admin pertama'
    say '     Dipakai untuk login ke panel. Bisa diubah nanti dari dalam panel.'
    while :; do
      ask '     Email admin' ''
      case "$REPLY_VAL" in
        *?@?*.?*) ADMIN_EMAIL=$REPLY_VAL; break ;;
        '') say '     Email wajib diisi.' ;;
        *) say '     Format email tidak valid.' ;;
      esac
    done
  fi

  if placeholder "$ADMIN_PASSWORD"; then
    say ''
    say '     Password minimal 8 karakter. Ketikan tidak ditampilkan.'
    while :; do
      ask_secret '     Password admin'
      _p1=$REPLY_VAL
      if [ "${#_p1}" -lt 8 ]; then
        say '     Terlalu pendek — minimal 8 karakter.'
        continue
      fi
      ask_secret '     Ulangi password'
      if [ "$_p1" != "$REPLY_VAL" ]; then
        say '     Tidak sama, coba lagi.'
        continue
      fi
      ADMIN_PASSWORD=$_p1
      break
    done
    say 'OK   kredensial admin disimpan'
    say ''
  fi

  # 4. HTTPS. Satu-satunya pilihan yang bisa membuat login gagal tanpa pesan
  #    error kalau salah, jadi ditanyakan eksplisit dengan default aman.
  rule
  say '4/4  Akses panel'
  say '     Panel di balik reverse proxy HTTPS? Jawab n kalau diakses'
  say '     langsung lewat http://ip-server:880 — cookie sesi tidak akan'
  say '     terkirim di HTTP plain kalau ini diaktifkan.'
  ask_yn '     Pakai HTTPS' 'n'
  [ "$REPLY_VAL" = y ] && COOKIE_SECURE=1 || COOKIE_SECURE=0
  say ''
fi

# --- mode non-interaktif -----------------------------------------------------
# Tanpa TTY tidak ada yang bisa ditanyai. Generate yang bisa digenerate, lalu
# berhenti: boot dengan kredensial admin contoh lebih buruk daripada gagal.
if [ -n "$NEED" ] && [ "$TTY" != 1 ]; then
  placeholder "$DB_PASSWORD" && DB_PASSWORD=$(gen 24)
  placeholder "$DB_ROOT_PASSWORD" && DB_ROOT_PASSWORD=$(gen 24)
  placeholder "$SESSION_SECRET" && SESSION_SECRET=$(gen 32)
fi

# --- tulis .env --------------------------------------------------------------
# Lewat file sementara supaya sed -i (beda perilaku di BSD dan GNU) tak dipakai,
# dan supaya .env lama tidak pernah setengah tertulis kalau skrip mati di tengah.
umask 077
{
  say '# Dibuat oleh setup.sh. Jangan di-commit — file ini ada di .gitignore.'
  say "DB_PASSWORD=$(esc "$DB_PASSWORD")"
  say "DB_ROOT_PASSWORD=$(esc "$DB_ROOT_PASSWORD")"
  say "SESSION_SECRET=$(esc "$SESSION_SECRET")"
  say "ADMIN_EMAIL=$(esc "$ADMIN_EMAIL")"
  say "ADMIN_PASSWORD=$(esc "$ADMIN_PASSWORD")"
  say '# 1 hanya kalau panel dilayani lewat HTTPS (di balik reverse proxy).'
  say '# Membiarkannya 1 di HTTP plain membuat cookie login tidak terkirim.'
  say "COOKIE_SECURE=$COOKIE_SECURE"
} > .env.tmp
mv .env.tmp .env
chmod 600 .env 2>/dev/null || true

# Placeholder yang masih tersisa berarti mode non-interaktif, atau wizard
# di-skip. Berhenti dengan menyebut baris mana yang perlu diisi.
LEFT=$(grep -n '=change-\|=$' .env | sed 's/=.*/=.../' || true)
if [ -n "$LEFT" ]; then
  say ''
  say 'Masih ada nilai yang belum diisi di .env:'
  say "$LEFT"
  say ''
  say 'Sunting .env lalu jalankan ./setup.sh lagi.'
  exit 1
fi
say 'OK  .env lengkap'

# --- jalankan ----------------------------------------------------------------
say ''
say '--> docker compose up -d --build'
say '    build pertama mengunduh image, bisa beberapa menit.'
say ''
docker compose up -d --build

# Tunggu panel menjawab: migrasi database jalan saat start, jadi ada jeda antara
# container "up" dan panel benar-benar melayani.
#
# Probe ke /health, bukan /login: /login sudah 200 begitu Express mengikat port,
# padahal migrasi bisa belum selesai dan halaman pertama langsung error. /health
# menanyakan database (SELECT 1) dan menjawab 503 selama belum siap, jadi 200 di
# sini benar-benar berarti panel bisa dipakai.
if command -v curl >/dev/null 2>&1; then
  printf 'menunggu panel siap'
  i=0
  while [ "$i" -lt 60 ]; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:880/health 2>/dev/null)" = "200" ]; then
      say ''
      say ''
      rule
      say '  Siap.'
      rule
      say "  Panel   http://localhost:880"
      say "  Login   $ADMIN_EMAIL"
      say ''
      say '  Langkah berikutnya:'
      say '  1. Menu Controller  -> tambahkan UniFi controller (IP + shared secret)'
      say '  2. Di UniFi         -> buat RADIUS profile ke server ini,'
      say '                         auth 1812/udp, accounting 1813/udp'
      say '  3. Di UniFi         -> aktifkan MAC authentication di SSID'
      say '  4. Menu SSID        -> aktifkan SSID yang muncul otomatis'
      say '  Tanpa restart: controller baru dikenali pada paket pertama, perubahan'
      say '  IP atau shared secret berlaku paling lama 5 menit.'
      rule
      exit 0
    fi
    printf '.'
    sleep 2
    i=$((i + 1))
  done
  say ''
  say 'Panel belum menjawab setelah 120 detik. Cek: docker compose logs web'
  exit 1
fi

say ''
say 'OK  container jalan. Buka http://localhost:880'
say '    (curl tidak ada, jadi kesiapan panel tidak diperiksa)'
