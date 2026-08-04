#!/bin/sh
# Update MACan ke versi terbaru dari git, tanpa menyentuh database.
#
# Yang dijamin skrip ini:
#   - container db tidak pernah di-stop, di-rebuild, atau dihapus
#   - `down` dan `down -v` tidak pernah dipanggil, jadi volume db_data aman
#   - backup harus berhasil sebelum apa pun diubah; gagal backup = batal
#   - dijalankan sebagai pemilik repo, bukan root: tidak ada file baru milik root
#
# ponytail: sh POSIX, tanpa dependensi selain docker dan git. Tidak ada langkah
# migrasi terpisah — web/src/migrate.js jalan sendiri saat container web start
# (app.js: migrate().then(ensureAdmin).then(listen)), jadi /health yang menjawab
# 200 sekaligus membuktikan perubahan schema sudah diterapkan. Menambah `docker
# compose exec web node -e migrate` di sini hanya akan menjalankannya dua kali.
set -eu

cd "$(dirname "$0")"

say() { printf '%s\n' "$*"; }
die() { printf '\ngagal: %s\n' "$*" >&2; exit 1; }
rule() { say '------------------------------------------------------------'; }

BACKUP_DIR=backups
KEEP=10

# --- prasyarat ---------------------------------------------------------------
# Root ditolak, bukan diizinkan "biar aman": `git pull` sebagai root meninggalkan
# objek milik root di .git, dan sejak itu pemilik repo tidak bisa pull lagi tanpa
# sudo — tiap update memperdalam kerusakannya. Jalankan sebagai pemilik repo yang
# ada di grup docker; kalau `docker compose` minta sudo, yang salah adalah hak
# akses .env, bukan skrip ini.
if [ "$(id -u)" = 0 ]; then
  die 'jangan jalankan sebagai root/sudo. Jalankan sebagai pemilik repo: ./update.sh'
fi

command -v docker >/dev/null 2>&1 || die 'docker tidak ditemukan.'
docker compose version >/dev/null 2>&1 \
  || die 'plugin "docker compose" tidak tersedia (butuh Compose v2).'
command -v git >/dev/null 2>&1 || die 'git tidak ditemukan.'
[ -f compose.yaml ] || die 'compose.yaml tidak ada — jalankan dari root proyek.'
[ -f .env ] || die '.env tidak ada. Ini instalasi baru? Jalankan ./setup.sh.'
# -r, bukan hanya -f: compose.yaml menginterpolasi ${DB_PASSWORD} dan kawan-kawan
# dari .env, jadi .env yang tidak terbaca membuat setiap perintah compose gagal
# dengan pesan yang tidak menyebut penyebabnya sama sekali.
[ -r .env ] || die ".env tidak bisa dibaca oleh $(id -un). Perbaiki sekali:
    sudo chown $(id -un):$(id -gn) .env && chmod 600 .env"
[ -d .git ] || die 'bukan git clone — tidak ada yang bisa di-pull.'
# Objek milik root di .git membuat pull berikutnya gagal. Deteksi sekarang, saat
# masih satu perintah untuk dibereskan. head -n1, bukan find -quit: -quit hanya
# ada di GNU find, sedangkan pipa yang ditutup head sudah menghentikan find.
if [ -n "$(find .git ! -user "$(id -un)" 2>/dev/null | head -n 1)" ]; then
  die "ada objek milik user lain di .git (sisa pernah dijalankan pakai sudo). Perbaiki:
    sudo chown -R $(id -un):$(id -gn) .git"
fi

say ''
rule
say '  MACan — update'
rule

# --- 1. backup ---------------------------------------------------------------
# Wajib berhasil. Dump lewat `docker exec` langsung ke container, memakai
# MARIADB_ROOT_PASSWORD dari env container itu sendiri: .env tidak perlu dibaca
# dan password tidak pernah muncul di command line host.
say ''
say '[1/5] Backup database'

DB=$(docker compose ps -q db 2>/dev/null || true)
[ -n "$DB" ] || die 'container db tidak jalan. Backup tidak mungkin, update dibatalkan.'
[ "$(docker inspect -f '{{.State.Running}}' "$DB" 2>/dev/null || true)" = true ] \
  || die 'container db ada tapi tidak running. Perbaiki dulu, jangan update.'

# Dump berisi shared secret RADIUS dan token telegram — owner-only, dan mkdir
# mode dimasak umask, jadi chmod setelahnya yang benar-benar menjamin 0700.
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" 2>/dev/null || true
FILE="$BACKUP_DIR/macan_$(date +%Y%m%d_%H%M%S).sql"
umask 077

# --single-transaction: dump konsisten tanpa mengunci tabel, jadi RADIUS tetap
# bisa menjawab auth selama backup berjalan.
if ! docker exec "$DB" sh -c \
     'exec mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction macan' \
     > "$FILE" 2>"$FILE.err"; then
  say "  pesan dari mariadb-dump: $(tr -d '\r' < "$FILE.err" | tail -n 3)"
  rm -f "$FILE" "$FILE.err"
  die 'backup database gagal. Update dibatalkan supaya data tidak dipertaruhkan.'
fi
rm -f "$FILE.err"

# File 0 byte atau hanya berisi header komentar berarti dump tidak jadi.
if ! grep -q 'CREATE TABLE' "$FILE"; then
  rm -f "$FILE"
  die 'file backup tidak berisi satu pun CREATE TABLE. Update dibatalkan.'
fi
say "OK    $FILE ($(wc -c < "$FILE" | tr -d ' ') byte)"

# --- 2. tarik kode -----------------------------------------------------------
say ''
say '[2/5] Tarik kode terbaru'
BEFORE=$(git rev-parse HEAD)
if ! git pull --ff-only origin main; then
  say ''
  say 'Ada perubahan lokal yang menghalangi, atau riwayat sudah bercabang.'
  say 'Lihat dulu: git status'
  say 'Kalau perubahan lokal tidak dibutuhkan: git stash'
  die 'git pull gagal. Belum ada yang diubah, container masih versi lama.'
fi
AFTER=$(git rev-parse HEAD)
if [ "$BEFORE" = "$AFTER" ]; then
  say 'OK    sudah versi terbaru — image tetap di-rebuild untuk memastikan'
  say '      container jalan dari kode yang sekarang ada di disk.'
else
  say "OK    $(git rev-list --count "$BEFORE..$AFTER") commit baru"
fi

# --- 3. build ----------------------------------------------------------------
# Hanya web dan radius. Service db memakai image resmi mariadb:11 dan tidak
# punya build context, jadi tidak mungkin ikut ter-rebuild.
#
# radius wajib ikut: file konfigurasinya (sql.conf, default.conf) di-COPY ke
# dalam image, bukan di-mount, jadi restart saja tidak memuat perubahan.
say ''
say '[3/5] Build image web dan radius (db tidak disentuh)'
say '      bisa beberapa menit.'
if ! docker compose build web radius; then
  say ''
  say "Backup ada di: $FILE"
  die 'build gagal. Container yang sekarang masih jalan dengan versi lama.'
fi
say 'OK    image ter-build'

# --- 4. ganti container ------------------------------------------------------
# --no-deps supaya db tidak ikut disentuh sama sekali. Tanpa itu Compose akan
# mengevaluasi depends_on dan bisa merekreasi db.
say ''
say '[4/5] Ganti container web dan radius'
if ! docker compose up -d --no-deps --force-recreate web radius; then
  say ''
  say "Backup ada di: $FILE"
  die 'container gagal start. Cek: docker compose logs web radius'
fi
say 'OK    container jalan'

# --- 5. tunggu siap ----------------------------------------------------------
# /health menanyakan database, jadi 200 di sini juga membuktikan migrasi yang
# jalan saat start sudah selesai. Probe dari dalam container web supaya tidak
# butuh curl di host dan tidak peduli port host dipetakan ke mana.
say ''
say '[5/5] Tunggu panel siap'
i=0
READY=0
while [ "$i" -lt 60 ]; do
  if docker compose exec -T web node -e '
      require("http").get({host:"127.0.0.1",port:880,path:"/health"},
        r => process.exit(r.statusCode === 200 ? 0 : 1))
        .on("error", () => process.exit(1));
    ' >/dev/null 2>&1; then
    READY=1
    break
  fi
  printf '.'
  sleep 2
  i=$((i + 1))
done
say ''
if [ "$READY" != 1 ]; then
  # Penyebab paling sering di titik ini adalah migrasi schema yang gagal: web
  # memanggil migrate() sebelum listen(), jadi DDL yang error membuat container
  # restart terus dan /health tidak pernah 200. Log-nya dicetak langsung supaya
  # pesan SQL-nya terbaca tanpa perlu perintah kedua.
  say 'Log terakhir container web:'
  docker compose logs --tail 20 web 2>&1 || true
  say ''
  say "Backup ada di: $FILE"
  die 'panel tidak menjawab /health setelah 120 detik.'
fi
say 'OK    /health menjawab 200'

# --- bersihkan backup lama ---------------------------------------------------
# ls -1t, bukan find -printf: -printf hanya ada di GNU find.
OLD=$(ls -1t "$BACKUP_DIR"/macan_*.sql 2>/dev/null | tail -n +$((KEEP + 1)) || true)
if [ -n "$OLD" ]; then
  printf '%s\n' "$OLD" | while IFS= read -r f; do rm -f "$f"; done
  say "OK    backup lama dihapus, $KEEP terbaru disimpan"
fi

say ''
rule
say '  Update selesai.'
rule
say "  Versi   $(git rev-parse --short HEAD)"
say "  Backup  $FILE"
say ''
say '  Database tidak pernah di-stop selama update ini.'
say ''
say '  Kalau ada yang salah dan perlu kembali ke data sebelum update:'
say "    docker exec -i $(docker compose ps --format '{{.Name}}' db) \\"
say '      sh -c '\''exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" macan'\'' \'
say "      < $FILE"
rule
