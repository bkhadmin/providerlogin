'use strict';

const { pool } = require('./db');

/**
 * Upsert a user from Provider profile data.
 * If account_id exists → UPDATE; otherwise → INSERT.
 * @param {object} profile - Provider profile from API
 * @returns {Promise<number>} userId (internal DB id)
 */
async function upsertUser(profile) {
  const sql = `
    INSERT INTO users (
      account_id, provider_id, hash_cid, username,
      title_th, special_title_th, firstname_th, lastname_th,
      title_en, special_title_en, firstname_en, lastname_en,
      first_login_at, last_login_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    ON DUPLICATE KEY UPDATE
      provider_id      = VALUES(provider_id),
      hash_cid         = VALUES(hash_cid),
      username         = VALUES(username),
      title_th         = VALUES(title_th),
      special_title_th = VALUES(special_title_th),
      firstname_th     = VALUES(firstname_th),
      lastname_th      = VALUES(lastname_th),
      title_en         = VALUES(title_en),
      special_title_en = VALUES(special_title_en),
      firstname_en     = VALUES(firstname_en),
      lastname_en      = VALUES(lastname_en),
      last_login_at    = NOW()
  `;

  const params = [
    profile.account_id   ?? null,
    profile.provider_id  ?? null,
    profile.hash_cid     ?? null,
    profile.username     ?? null,
    profile.title_th     ?? null,
    profile.special_title_th ?? null,
    profile.firstname_th ?? null,
    profile.lastname_th  ?? null,
    profile.title_en     ?? null,
    profile.special_title_en ?? null,
    profile.firstname_en ?? null,
    profile.lastname_en  ?? null,
  ];

  const [result] = await pool.execute(sql, params);
  // insertId จะมีค่าเสมอ (ทั้ง INSERT และ ON DUPLICATE KEY UPDATE)
  return result.insertId || await getUserIdByAccountId(profile.account_id);
}

/**
 * Get internal userId from account_id
 */
async function getUserIdByAccountId(accountId) {
  const [rows] = await pool.execute(
    'SELECT id FROM users WHERE account_id = ? LIMIT 1',
    [accountId]
  );
  return rows[0]?.id ?? null;
}

/**
 * Sync user organizations (delete old → insert fresh)
 * @param {number} userId
 * @param {Array} organizations - array from Provider profile
 */
async function syncOrganizations(userId, organizations = []) {
  if (!userId) return;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // ลบ organizations เดิมทั้งหมดก่อน
    await conn.execute('DELETE FROM user_organizations WHERE user_id = ?', [userId]);

    // Insert ใหม่ทุกองค์กร
    if (organizations.length > 0) {
      const sql = `
        INSERT INTO user_organizations
          (user_id, hcode, hname_th, hname_en, position, expertise,
           is_hr_admin, is_director, moph_access_token_idp)
        VALUES ?
      `;
      const values = organizations.map(org => [
        userId,
        org.hcode      ?? null,
        org.hname_th   ?? null,
        org.hname_en   ?? null,
        org.position   ?? null,
        org.expertise  ?? null,
        org.is_hr_admin  ? 1 : 0,
        org.is_director  ? 1 : 0,
        org.moph_access_token_idp ?? null,
      ]);
      // ใช้ query (ไม่ใช่ execute) เพราะต้องการ bulk INSERT ด้วย VALUES ?
      await conn.query(sql, [values]);
    }

    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * Record a login event in login_logs
 * @param {object} opts
 */
async function recordLoginLog({ userId, accountId, username, ip, userAgent, event, errorMsg }) {
  await pool.execute(
    `INSERT INTO login_logs
       (user_id, account_id, username, ip_address, user_agent, event, error_msg)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      userId    ?? null,
      accountId ?? null,
      username  ?? null,
      ip        ?? 'unknown',
      userAgent ?? null,
      event,
      errorMsg  ?? null,
    ]
  );
}

/**
 * Get recent login history for a user (for dashboard display)
 * @param {string} accountId
 * @param {number} limit
 */
async function getLoginHistory(accountId, limit = 10) {
  const [rows] = await pool.execute(
    `SELECT event, ip_address, user_agent, created_at
     FROM login_logs
     WHERE account_id = ?
     ORDER BY created_at DESC
     LIMIT ?`,
    [accountId, limit]
  );
  return rows;
}

module.exports = { upsertUser, syncOrganizations, recordLoginLog, getLoginHistory };
