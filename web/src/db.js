const mysql = require('mysql2/promise');

// Satu sumber zona waktu untuk seluruh aplikasi. TZ=Asia/Jakarta di compose.yaml
// mengatur proses Node; offset itu lalu dipaksakan ke setiap koneksi MariaDB.
//
// Kenapa tidak dibiarkan default: MariaDB memakai time_zone = SYSTEM, yaitu zona
// container db — bukan zona klien. Kalau web dan db beda zona, dashboard.js
// membandingkan DATE_FORMAT(created_at, '%Y-%m-%d %H:00') (dirender di zona sesi
// DB) dengan kunci jam yang dibentuk dari waktu lokal Node: semua bucket luput
// dan grafik 24 jam terbaca nol tanpa satu pun error. Memakai offset, bukan nama
// zona, supaya tidak bergantung pada tabel tzinfo MariaDB.
//
// ponytail: offset tetap, bukan zona dengan DST. Asia/Jakarta tidak punya DST;
// kalau nanti dipakai di zona yang punya, ganti ke nama zona dan pastikan
// mysql_tzinfo_to_sql sudah dijalankan di container db.
const offsetMinutes = -new Date().getTimezoneOffset();
const pad = n => String(Math.abs(n)).padStart(2, '0');
const TZ_OFFSET = `${offsetMinutes < 0 ? '-' : '+'}${pad(Math.trunc(offsetMinutes / 60))}:${pad(offsetMinutes % 60)}`;

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'macan',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'macan',
  waitForConnections: true,
  connectionLimit: 10,
  timezone: TZ_OFFSET
});

// `timezone` hanya mengatur cara mysql2 menafsirkan string tanggal yang diterima.
// NOW(), CURRENT_TIMESTAMP, dan DATE_FORMAT dievaluasi di server memakai time_zone
// sesi — yang default-nya SYSTEM, zona container db. Setel per koneksi supaya
// keduanya sepakat. Lewat pool.pool (pool callback di bawah wrapper promise)
// karena hanya itu yang memancarkan event 'connection'.
pool.pool.on('connection', conn => conn.query(`SET time_zone = '${TZ_OFFSET}'`));

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// DDL and multi-statement-free raw queries: prepared protocol rejects some DDL.
async function raw(sql) {
  const [rows] = await pool.query(sql);
  return rows;
}

async function transaction(callback) {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    // A failing rollback must not replace the error that caused it — that is the
    // one the caller needs to see. Attach it instead.
    try {
      await connection.rollback();
    } catch (rollbackError) {
      error.rollbackError = rollbackError;
    }
    throw error;
  } finally {
    connection.release();
  }
}

module.exports = { pool, query, raw, transaction, TZ_OFFSET };
