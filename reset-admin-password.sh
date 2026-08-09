#!/usr/bin/env bash
# Reset password admin MACan langsung di container MariaDB.
# Reusable ops tool — tidak menyimpan secret apa pun di repo.
#
# Pakai:
#   ADMIN_EMAIL='user@contoh.com' ADMIN_HASH='$2b$12$...' bash reset-admin-password.sh
#
# Generate hash bcrypt (rounds 12 = sama dengan ensureAdmin()) di mesin yang
# punya node + bcrypt (mis. container web, atau lokal pakai bcrypt repo):
#   cd web && node -e "const b=require('bcrypt');b.hash('PASSWORD_BARU',12).then(h=>console.log(h))"
# Copy output, jadikan ADMIN_HASH. Hash satu arah — aman lewat env var.
set -euo pipefail

CONTAINER="${CONTAINER:-radiusmac-db-1}"
DB_NAME="${DB_NAME:-macan}"
DB_ROOT_PASS="${DB_ROOT_PASS:?DB_ROOT_PASS wajib (ambil dari .env, DB_ROOT_PASSWORD)}"
EMAIL="${ADMIN_EMAIL:?ADMIN_EMAIL wajib, contoh: ADMIN_EMAIL='a@b.com'}"
HASH="${ADMIN_HASH:?ADMIN_HASH wajib: hash bcrypt rounds 12 untuk password baru}"

# 1. Container ada?
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "ERROR: container '$CONTAINER' tidak berjalan." >&2
  echo "Container aktif:"; docker ps --format '  {{.Names}}' >&2
  exit 1
fi

# 2. Email terdaftar? (bukan asumsi — kalau salah email, UPDATE 0 baris diam-diam)
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

# 3. Reset password + pastikan enabled.
docker exec -i "$CONTAINER" mariadb -uroot -p"$DB_ROOT_PASS" "$DB_NAME" \
  -e "UPDATE admins SET password_hash='$HASH', enabled=1 WHERE email='$EMAIL';" 2>/dev/null

# 4. Verifikasi (email + enabled + hash prefix — bukan hash penuh, jangan bocor di log).
RESULT=$(docker exec -i "$CONTAINER" mariadb -uroot -p"$DB_ROOT_PASS" "$DB_NAME" \
  -N -B -e "SELECT CONCAT(email,' | enabled=',enabled,' | hash_prefix=',LEFT(password_hash,7)) FROM admins WHERE email='$EMAIL';" 2>/dev/null)

echo "OK. Password direset untuk:"
echo "  $RESULT"
echo "Login pakai email: $EMAIL  dan password baru yang sudah kamu pilih."
