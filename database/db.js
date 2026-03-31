'use strict';

const mysql = require('mysql2/promise');
const config = require('../config/config');
const { logger } = require('../middleware/audit');

// ─── Connection Pool ──────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:            config.db.host,
  port:            config.db.port,
  user:            config.db.user,
  password:        config.db.password,
  database:        config.db.name,
  connectionLimit: config.db.connectionLimit,
  waitForConnections: true,
  queueLimit:      0,
  charset:         'utf8mb4',
  timezone:        '+07:00',
  // Security: ปิดการ multi-statement ป้องกัน SQL injection ข้ามคำสั่ง
  multipleStatements: false,
});

// ─── Test Connection on Startup ───────────────────────────────────────────────
async function testConnection() {
  try {
    const conn = await pool.getConnection();
    logger.info({ event: 'DB_CONNECTED', message: `MySQL connected`, host: config.db.host, database: config.db.name });
    conn.release();
  } catch (err) {
    logger.error({
      event: 'DB_CONNECTION_FAILED',
      message: `Cannot connect to MySQL at ${config.db.host}:${config.db.port}/${config.db.name}`,
      error: err.message,
    });
    logger.warn({ event: 'DB_SKIPPED', message: 'Server starting WITHOUT database. Login will fail until MySQL is available.' });
    // ไม่ exit เพื่อให้ UI ยังเปิดได้ระหว่างทดสอบ — เอา process.exit(1) กลับมาใส่ตอน production
  }
}

module.exports = { pool, testConnection };
