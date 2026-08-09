#!/usr/bin/env bash
# Reset password admin MACan ke default (Arabika1927) via container MariaDB.
# Email di-input saat jalan. Kredensial DB dibaca otomatis dari .env (jangan
# hardcode). Pakai MYSQL_PWD (bukan -p) supaya password dgn special char aman
# dan tidak muncul di process list / warning.
#
# Pakai:  bash reset-admin-password.sh
# Lalu:   login pakai email yg dimasukkan + password Arabika1927.
#         GANTI password default ini segera setelah login (hash ada di repo).
set -euo pipefail

CONTAINER="${CONTAINER:-radiusmac-db-1}"
DB_NAME="${DB_NAME:-macan}"

# 1. Baca .env — cari di PWD, atau di parent (script bisa di-run dari repo root
#    atau dari subdir). Ambil DB_ROOT_PASSWORD (fallback DB_PASSWORD).
ENV_FILE=""
for f in "$PWD/.env" "$(dirname "$0")/.env" "$PWD/../.env"; do
  [ -f "$f" ] && { ENV_FILE="$f"; break; }
done
[ -n "$ENV_FILE" ] || { echo "ERROR: .env tidak ditemukan (cari di PWD / script dir / parent)." >&2; exit 1; }

# Source hanya baris DB_*, abaiin sisanya (jangan polusi env dgn kredensial lain).
# ponytail: grep + export, bukan `source .env` penuh — .env bisa punya baris non-shell
# (komentar, value dgn spasi) yg break sourcing. Hanya ambil DB_* aman.
DB_ROOT_PASS=""; DB_APP_PASS=""
while IFS='=' read -r key val; do
  case "$key" in
    DB_ROOT_PASSWORD) DB_ROOT_PASS="${val#\"}"; DB_ROOT_PASS="${DB_ROOT_PASS%\"}" ;;
    DB_PASSWORD)      DB_APP_PASS="${val#\"}";  DB_APP_PASS="${DB_APP_PASS%\"}" ;;
  esac
done < "$ENV_FILE"

# Prioritaskan root (bisa UPDATE admin); fallback ke app user (DB_PASSWORD) —
# user app `macan` punya akses penuh ke tabel admins di schema ini.
DB_PASS="$DB_ROOT_PASS"; DB_USER="root"
[ -n "$DB_PASS" ] || { DB_PASS="$DB_APP_PASS"; DB_USER="${DB_USER_APP:-macan}"; }
[ -n "$DB_PASS" ] || { echo "ERROR: DB_ROOT_PASSWORD / DB_PASSWORD tidak ada di $ENV_FILE." >&2; exit 1; }

# Hash bcrypt rounds 12 untuk "Arabika1927" — sama dgn ensureAdmin().
HASH='$2b$12$Cf9OdZP69u7KHcfrJmpUr.LmNh.b.yaQ2Et/hl2I1kmmOjsIk1FmS'

read -rp "Email admin yang direset: " EMAIL
[ -n "$EMAIL" ] || { echo "Email kosong." >&2; exit 1; }

# 2. Container ada?
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "ERROR: container '$CONTAINER' tidak berjalan." >&2
  echo "Container aktif:"; docker ps --format '  {{.Names}}' >&2
  exit 1
fi

# Helper: jalanin SQL via container. MYSQL_PWD via env container supaya password
# tidak lewat CLI (aman utk special char + tidak muncul di `ps`).
# ponytail: pakai `mariadb` langsung — container image mariadb:11 pasti punya
# client-nya. Deteksi command-v tanpa shell cuma bikin rusak (command = builtin).
sql() {
  docker exec -i -e MYSQL_PWD="$DB_PASS" "$CONTAINER" mariadb -u"$DB_USER" "$DB_NAME" "$@"
}

# 3. Email terdaftar? (bukan asumsi — kalau salah, UPDATE 0 baris diam-diam)
EXISTS=$(sql -N -B -e "SELECT COUNT(*) FROM admins WHERE email='$EMAIL';" 2>/dev/null) || {
  echo "ERROR: gagal koneksi DB sebagai '$DB_USER'. Cek $ENV_FILE (DB_ROOT_PASSWORD/DB_PASSWORD) + DB_NAME='$DB_NAME'." >&2
  echo "Detail error:" >&2
  sql -N -B -e "SELECT 1;" >&2 || true
  exit 1; }

if [ "$EXISTS" != "1" ]; then
  echo "ERROR: email '$EMAIL' tidak ditemukan di tabel admins." >&2
  echo "Email yang terdaftar:" >&2
  sql -N -B -e "SELECT email FROM admins;" 2>/dev/null >&2 || true
  exit 1
fi

# 4. Reset password ke default + pastikan enabled.
sql -e "UPDATE admins SET password_hash='$HASH', enabled=1 WHERE email='$EMAIL';" 2>/dev/null

# 5. Verifikasi (email + enabled + hash prefix — bukan hash penuh).
RESULT=$(sql -N -B -e "SELECT CONCAT(email,' | enabled=',enabled,' | hash_prefix=',LEFT(password_hash,7)) FROM admins WHERE email='$EMAIL';" 2>/dev/null)

echo "OK. Password direset ke default untuk:"
echo "  $RESULT"
echo "Login: $EMAIL / Arabika1927"
echo ">> Ganti password default ini segera setelah login."
