#!/bin/sh
# Bootstrap MACan: siapkan .env lalu jalankan compose. Aman dijalankan ulang.
#
# ponytail: sh POSIX, tanpa dependensi selain docker. Bukan Python/pip — proyek
# ini nol file .py; npm install sudah dijalankan di dalam web/Dockerfile.
set -eu

cd "$(dirname "$0")"
say() { printf '%s\n' "$*"; }
die() { printf 'gagal: %s\n' "$*" >&2; exit 1; }

# --- prasyarat ---------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die 'docker tidak ditemukan. Pasang Docker lebih dulu.'
docker compose version >/dev/null 2>&1 || die 'plugin "docker compose" tidak tersedia (butuh Compose v2).'
say "OK  docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo terpasang)"

# --- .env --------------------------------------------------------------------
# Kunci acak dibuat sekali di sini supaya tidak ada yang menjalankan MACan
# dengan SESSION_SECRET bawaan.
gen() {
  openssl rand -hex "$1" 2>/dev/null && return 0
  head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n' && return 0
  die 'tidak bisa membuat nilai acak: openssl dan /dev/urandom sama-sama tidak tersedia.'
}

if [ ! -f .env ]; then
  [ -f .env.example ] || die '.env.example hilang.'
  DBP=$(gen 24); DBR=$(gen 24); SES=$(gen 32)
  # Baca template baris demi baris, ganti hanya tiga kunci yang bisa digenerate.
  # Menulis lewat file sementara supaya sed -i (beda di BSD dan GNU) tak dipakai.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      DB_PASSWORD=*)      printf 'DB_PASSWORD=%s\n' "$DBP" ;;
      DB_ROOT_PASSWORD=*) printf 'DB_ROOT_PASSWORD=%s\n' "$DBR" ;;
      SESSION_SECRET=*)   printf 'SESSION_SECRET=%s\n' "$SES" ;;
      *)                  printf '%s\n' "$line" ;;
    esac
  done < .env.example > .env.tmp
  mv .env.tmp .env
  chmod 600 .env 2>/dev/null || true
  say 'OK  .env dibuat dari .env.example'
  say 'OK  DB_PASSWORD, DB_ROOT_PASSWORD, SESSION_SECRET digenerate acak'
else
  say 'OK  .env sudah ada, dibiarkan apa adanya'
fi

# Nilai contoh yang tersisa harus diisi manusia — email dan password admin tidak
# bisa ditebak skrip. Berhenti di sini, bukan boot dengan kredensial contoh.
if grep -q '=change-' .env 2>/dev/null; then
  say ''
  say 'Sunting .env dan isi nilai yang masih "change-...":'
  grep -n '=change-' .env | sed 's/=.*/=.../'
  say ''
  say 'Lalu jalankan ./setup.sh lagi.'
  exit 1
fi
say 'OK  .env lengkap'

# --- jalankan ----------------------------------------------------------------
say ''
say '--> docker compose up -d --build'
docker compose up -d --build

# Tunggu panel menjawab. Migrasi database jalan saat start, jadi ada jeda.
if command -v curl >/dev/null 2>&1; then
  printf 'menunggu panel siap'
  i=0
  while [ "$i" -lt 60 ]; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:880/login 2>/dev/null)" = "200" ]; then
      say ''
      say 'OK  panel siap di http://localhost:880'
      say '    login memakai ADMIN_EMAIL dan ADMIN_PASSWORD dari .env'
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
