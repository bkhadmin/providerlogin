'use strict';
/**
 * สร้าง superadmin account สำหรับ production
 * รัน: docker compose exec app node docker/create-admin.js
 *   หรือ: node docker/create-admin.js
 */
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool } = require('../database/db');

const USERNAME     = process.env.ADMIN_USERNAME || 'superadmin';
const PASSWORD     = process.env.ADMIN_PASSWORD || (() => { throw new Error('กรุณาตั้ง ADMIN_PASSWORD ใน .env'); })();
const DISPLAY_NAME = process.env.ADMIN_DISPLAY_NAME || 'Super Admin';

(async () => {
  try {
    const hash = await bcrypt.hash(PASSWORD, 12);
    const [result] = await pool.query(
      `INSERT INTO admin_accounts (username, password_hash, display_name, role, is_active)
       VALUES (?, ?, ?, 'superadmin', 1)
       ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), display_name = VALUES(display_name)`,
      [USERNAME, hash, DISPLAY_NAME]
    );
    const action = result.insertId ? 'สร้าง' : 'อัพเดต';
    console.log(`✅ ${action} superadmin "${USERNAME}" เรียบร้อยแล้ว`);
    process.exit(0);
  } catch (e) {
    console.error('❌ Error:', e.message);
    process.exit(1);
  }
})();
