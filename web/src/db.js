const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'macan',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'macan',
  waitForConnections: true,
  connectionLimit: 10
});

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
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

module.exports = { pool, query, raw, transaction };
