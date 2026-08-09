#!/usr/bin/env bash
# Reset password admin MACan ke default (Arabika1927) via container MariaDB.
# Email di-input saat jalan — tidak ada email personal di script.
#
# Pakai:  bash reset-admin-password.sh
# Lalu:   login pakai email yg dimasukkan + password Arabika1927.
#         GANTI password default ini segera setelah login (hash ada di repo).
set -euo pipefail

CONTAINER="${CONTAINER:-radiusmac-db-1}"
DB_NAME="${DB_NAME:-macan}"
DB_ROOT_PASS="${DB_ROOT_PASS:-rootsecret}"   # override lewat env kalau beda dari .env
# Hash bcrypt rounds 12 untuk password default "Arabika1927" — sama dengan
# rounds yg dipakai ensureAdmin() saat seeding. Hash satu arah, tapi password
# default ini tercatat di repo: ganti setelah login pertama.
HASH='$2b$12$Cf9OdZP69u7KHcfrJmpUr.LmNh.b.yaQ2Et/hl2I1kmmOjsIk1FmS'

read -rp "Email admin yang direset: " EMAIL
[ -n "$EMAIL" ] || { echo "Email kosong." >&2; exit 1; }

# 1. Container ada?
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "ERROR: container '$CONTAINER' tidak berjalan." >&2
  echo "Container aktif:"; docker ps --format '  {{.Names}}' >&2
  exit 1
fi

# 2. Email terdaftar? (bukan asumsi — kalau salah, UPDATE 0 baris diam-diam)
EXISTS=$(docker exec -i "$CONTAINER" mariadb -uroot -p"$DB_ROOT_PASS" "$DB_NAME" \
  -N -B -e "SELECT COUNT(*) FROM admins WHERE email='$EMAIL';" 2>/dev/null) || {
    echo "ERROR: gagal koneksi MariaDB. Cek DB_ROOT_PASS / DB_NAME / nama container." >&2; exit 1; }

if [ "$EXISTS" != "1" ]; then
  echo "ERROR: email '$EMAIL' tidak ditemukan di tabel admins." >&2
  echo "Email yang terdaftar:" >&2
  docker exec -i "$CONTAINER" mariadb -uroot -p"$DB_ROOT_PASS" "$DB_NAME" \
    -N -B -e "SELECT email FROM admins;" 2>/dev/null >&2 || true
  exit 1
fi

# 3. Reset password ke default + pastikan enabled.
docker exec -i "$CONTAINER" mariadb -uroot -p"$DB_ROOT_PASS" "$DB_NAME" \
  -e "UPDATE admins SET password_hash='$HASH', enabled=1 WHERE email='$EMAIL';" 2>/dev/null

# 4. Verifikasi (email + enabled + hash prefix — bukan hash penuh).
RESULT=$(docker exec -i "$CONTAINER" mariadb -uroot -p"$DB_ROOT_PASS" "$DB_NAME" \
  -N -B -e "SELECT CONCAT(email,' | enabled=',enabled,' | hash_prefix=',LEFT(password_hash,7)) FROM admins WHERE email='$EMAIL';" 2>/dev/null)

echo "OK. Password direset ke default untuk:"
echo "  $RESULT"
echo "Login: $EMAIL / Arabika1927"
echo ">> Ganti password default ini segera setelah login."
