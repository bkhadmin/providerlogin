'use strict';

const bcrypt = require('bcryptjs');
const { pool } = require('./db');

// Role hierarchy — สูงกว่า = มีสิทธิ์มากกว่า
const ROLE_LEVEL = { user: 1, admin2: 2, admin1: 3, superadmin: 4 };

function roleLevel(role) {
  return ROLE_LEVEL[role] ?? 0;
}

// ─── Admin Accounts ──────────────────────────────────────────

async function getAdminByUsername(username) {
  const [rows] = await pool.query(
    'SELECT * FROM admin_accounts WHERE username = ? AND is_active = 1',
    [username]
  );
  return rows[0] ?? null;
}

async function getAdminById(id) {
  const [rows] = await pool.query(
    'SELECT id, username, display_name, role, is_active, last_login_at, created_at FROM admin_accounts WHERE id = ?',
    [id]
  );
  return rows[0] ?? null;
}

async function listAdmins() {
  const [rows] = await pool.query(
    `SELECT id, username, display_name, role, is_active, last_login_at, created_at
     FROM admin_accounts ORDER BY role DESC, username ASC`
  );
  return rows;
}

async function createAdmin({ username, password, role = 'admin2', display_name = '' }) {
  const hash = await bcrypt.hash(password, 12);
  const [result] = await pool.query(
    'INSERT INTO admin_accounts (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)',
    [username, hash, display_name || username, role]
  );
  return result.insertId;
}

async function updateAdmin(id, { display_name, role, is_active, password }) {
  const fields = [];
  const values = [];

  if (display_name !== undefined) { fields.push('display_name = ?'); values.push(display_name); }
  if (role        !== undefined) { fields.push('role = ?');         values.push(role); }
  if (is_active   !== undefined) { fields.push('is_active = ?');    values.push(is_active ? 1 : 0); }
  if (password) {
    const hash = await bcrypt.hash(password, 12);
    fields.push('password_hash = ?');
    values.push(hash);
  }

  if (!fields.length) return;
  values.push(id);
  await pool.query(`UPDATE admin_accounts SET ${fields.join(', ')} WHERE id = ?`, values);
}

async function deleteAdmin(id) {
  await pool.query('DELETE FROM admin_accounts WHERE id = ?', [id]);
}

async function updateAdminLastLogin(id) {
  await pool.query('UPDATE admin_accounts SET last_login_at = NOW() WHERE id = ?', [id]);
}

async function verifyAdminPassword(admin, password) {
  return bcrypt.compare(password, admin.password_hash);
}

async function saveTotpSecret(id, secret) {
  await pool.query('UPDATE admin_accounts SET totp_secret = ? WHERE id = ?', [secret, id]);
}

async function clearTotpSecret(id) {
  await pool.query('UPDATE admin_accounts SET totp_secret = NULL WHERE id = ?', [id]);
}

async function getAdminByIdFull(id) {
  const [rows] = await pool.query(
    'SELECT * FROM admin_accounts WHERE id = ?',
    [id]
  );
  return rows[0] ?? null;
}

// ─── Applications ────────────────────────────────────────────

async function listApps() {
  const [rows] = await pool.query(
    'SELECT * FROM applications ORDER BY sort_order ASC, id ASC'
  );
  return rows;
}

async function listActiveApps() {
  const [rows] = await pool.query(
    'SELECT * FROM applications WHERE is_active = 1 ORDER BY sort_order ASC, id ASC'
  );
  return rows;
}

async function createApp({ app_id, name, description = '', icon = '🔷', url, required_expertise = null, hcode_whitelist = null, sort_order = 0 }) {
  const [result] = await pool.query(
    'INSERT INTO applications (app_id, name, description, icon, url, required_expertise, hcode_whitelist, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [app_id, name, description, icon, url, required_expertise || null, hcode_whitelist || null, sort_order]
  );
  return result.insertId;
}

async function updateApp(id, { name, description, icon, url, required_expertise, hcode_whitelist, is_active, sort_order } = {}) {
  const fields = [];
  const values = [];

  if (name               !== undefined) { fields.push('name = ?');               values.push(name); }
  if (description        !== undefined) { fields.push('description = ?');        values.push(description); }
  if (icon               !== undefined) { fields.push('icon = ?');               values.push(icon); }
  if (url                !== undefined) { fields.push('url = ?');                values.push(url); }
  if (required_expertise !== undefined) { fields.push('required_expertise = ?'); values.push(required_expertise || null); }
  if (hcode_whitelist    !== undefined) { fields.push('hcode_whitelist = ?');    values.push(hcode_whitelist || null); }
  if (is_active          !== undefined) { fields.push('is_active = ?');          values.push(is_active ? 1 : 0); }
  if (sort_order         !== undefined) { fields.push('sort_order = ?');         values.push(sort_order); }

  if (!fields.length) return;
  values.push(id);
  await pool.query(`UPDATE applications SET ${fields.join(', ')} WHERE id = ?`, values);
}

async function deleteApp(id) {
  await pool.query('DELETE FROM applications WHERE id = ?', [id]);
}

// ─── Provider Users ──────────────────────────────────────────

async function listProviderUsers() {
  const [rows] = await pool.query(`
    SELECT u.id, u.account_id, u.provider_id, u.username,
           u.title_th, u.firstname_th, u.lastname_th, u.special_title_th,
           u.first_login_at, u.last_login_at,
           GROUP_CONCAT(DISTINCT uo.hname_th ORDER BY uo.id SEPARATOR ', ') AS orgs,
           GROUP_CONCAT(DISTINCT uo.position  ORDER BY uo.id SEPARATOR ', ') AS positions
    FROM users u
    LEFT JOIN user_organizations uo ON uo.user_id = u.id
    GROUP BY u.id
    ORDER BY u.last_login_at DESC
  `);
  return rows;
}

async function getProviderUserApps(userId) {
  // สิทธิ์ effective: individual override > position rule > default (allowed)
  const [rows] = await pool.query(
    `SELECT a.app_id, a.name, a.icon,
            CASE
              WHEN uaa.id IS NOT NULL THEN uaa.is_allowed
              WHEN paa.id IS NOT NULL THEN paa.is_allowed
              ELSE 1
            END AS is_allowed,
            CASE
              WHEN uaa.id IS NOT NULL THEN 'individual'
              WHEN paa.id IS NOT NULL THEN 'position'
              ELSE 'default'
            END AS permission_source,
            uaa.id AS override_id
     FROM applications a
     LEFT JOIN user_app_access uaa
            ON uaa.app_id = a.app_id AND uaa.user_id = ?
     LEFT JOIN (
       SELECT paa2.app_id, paa2.is_allowed, paa2.id
       FROM position_app_access paa2
       WHERE paa2.position IN (
         SELECT position FROM user_organizations WHERE user_id = ? AND position IS NOT NULL
       )
       ORDER BY paa2.is_allowed ASC LIMIT 1
     ) paa ON paa.app_id = a.app_id
     WHERE a.is_active = 1
     ORDER BY a.sort_order ASC`,
    [userId, userId]
  );
  return rows;
}

async function setUserAppAccess(userId, appId, isAllowed, grantedBy) {
  await pool.query(
    `INSERT INTO user_app_access (user_id, app_id, is_allowed, granted_by)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE is_allowed = VALUES(is_allowed), granted_by = VALUES(granted_by)`,
    [userId, appId, isAllowed ? 1 : 0, grantedBy]
  );
}

async function resetUserAppAccess(userId, appId) {
  await pool.query(
    'DELETE FROM user_app_access WHERE user_id = ? AND app_id = ?',
    [userId, appId]
  );
}

async function deleteProviderUser(userId) {
  await pool.query('DELETE FROM users WHERE id = ?', [userId]);
}

// ─── Position App Access ──────────────────────────────────────

async function listPositions() {
  const [rows] = await pool.query(
    `SELECT DISTINCT uo.position,
            COUNT(DISTINCT uo.user_id) AS user_count
     FROM user_organizations uo
     WHERE uo.position IS NOT NULL AND uo.position != ''
     GROUP BY uo.position
     ORDER BY uo.position ASC`
  );
  return rows;
}

async function getPositionApps(position) {
  const [rows] = await pool.query(
    `SELECT a.app_id, a.name, a.icon,
            COALESCE(paa.is_allowed, 1) AS is_allowed,
            paa.id
     FROM applications a
     LEFT JOIN position_app_access paa ON paa.app_id = a.app_id AND paa.position = ?
     WHERE a.is_active = 1
     ORDER BY a.sort_order ASC`,
    [position]
  );
  return rows;
}

async function setPositionAppAccess(position, appId, isAllowed, grantedBy) {
  await pool.query(
    `INSERT INTO position_app_access (position, app_id, is_allowed, granted_by)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE is_allowed = VALUES(is_allowed), granted_by = VALUES(granted_by)`,
    [position, appId, isAllowed ? 1 : 0, grantedBy]
  );
}

async function resetPositionAppAccess(position, appId) {
  await pool.query(
    'DELETE FROM position_app_access WHERE position = ? AND app_id = ?',
    [position, appId]
  );
}

// ─── Stats (Dashboard) ────────────────────────────────────────

async function getAdminStats() {
  const [[{ total_users }]]      = await pool.query('SELECT COUNT(*) AS total_users FROM users');
  const [[{ logins_today }]]     = await pool.query("SELECT COUNT(*) AS logins_today FROM login_logs WHERE event='LOGIN_SUCCESS' AND DATE(created_at)=CURDATE()");
  const [[{ failures_today }]]   = await pool.query("SELECT COUNT(*) AS failures_today FROM login_logs WHERE event IN ('LOGIN_FAILURE','LOGIN_NO_PROVIDER_ID','LOGIN_UNAUTHORIZED') AND DATE(created_at)=CURDATE()");
  const [[{ active_apps }]]      = await pool.query('SELECT COUNT(*) AS active_apps FROM applications WHERE is_active=1');
  const [[{ app_opens_today }]]  = await pool.query("SELECT COUNT(*) AS app_opens_today FROM app_access_logs WHERE DATE(created_at)=CURDATE()");
  const [[{ total_admins }]]     = await pool.query("SELECT COUNT(*) AS total_admins FROM admin_accounts WHERE is_active=1");

  // top 5 apps วันนี้
  const [top_apps] = await pool.query(
    `SELECT app_id, app_name, COUNT(*) AS cnt
     FROM app_access_logs WHERE DATE(created_at)=CURDATE()
     GROUP BY app_id, app_name ORDER BY cnt DESC LIMIT 5`
  );
  // logins 7 วัน
  const [login_trend] = await pool.query(
    `SELECT DATE(created_at) AS day, COUNT(*) AS cnt
     FROM login_logs WHERE event='LOGIN_SUCCESS' AND created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
     GROUP BY DATE(created_at) ORDER BY day ASC`
  );
  return { total_users, logins_today, failures_today, active_apps, app_opens_today, total_admins, top_apps, login_trend };
}

// ─── Login Logs ───────────────────────────────────────────────

async function getLoginLogs({ limit = 100, offset = 0, event = null, days = 7 } = {}) {
  const conditions = ['l.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)'];
  const values = [days];
  if (event) { conditions.push('l.event = ?'); values.push(event); }
  const where = conditions.join(' AND ');
  const [rows] = await pool.query(
    `SELECT l.id, l.account_id, l.username, l.event, l.ip_address, l.error_msg, l.created_at,
            CONCAT(u.firstname_th,' ',u.lastname_th) AS fullname_th
     FROM login_logs l
     LEFT JOIN users u ON u.id = l.user_id
     WHERE ${where}
     ORDER BY l.created_at DESC LIMIT ? OFFSET ?`,
    [...values, limit, offset]
  );
  return rows;
}

// ─── Admin Audit Logs ─────────────────────────────────────────

async function addAuditLog({ adminId, username, role, action, targetType, targetId, detail, ip }) {
  await pool.query(
    `INSERT INTO admin_audit_logs (admin_id, username, role, action, target_type, target_id, detail, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [adminId ?? null, username ?? null, role ?? null, action, targetType ?? null, targetId ? String(targetId) : null,
     detail ? JSON.stringify(detail) : null, ip ?? null]
  );
}

async function getAuditLogs({ limit = 100, offset = 0, days = 30 } = {}) {
  const [rows] = await pool.query(
    `SELECT * FROM admin_audit_logs
     WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
     ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [days, limit, offset]
  );
  return rows;
}

// ─── App Access Logs ──────────────────────────────────────────

async function addAppAccessLog({ userId, accountId, username, appId, appName, ip, userAgent }) {
  await pool.query(
    `INSERT INTO app_access_logs (user_id, account_id, username, app_id, app_name, ip_address, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId ?? null, accountId ?? null, username ?? null, appId, appName ?? null, ip ?? null, userAgent ?? null]
  );
}

async function getAppAccessLogs({ limit = 100, offset = 0, appId = null, days = 7 } = {}) {
  const conditions = ['created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)'];
  const values = [days];
  if (appId) { conditions.push('app_id = ?'); values.push(appId); }
  const [rows] = await pool.query(
    `SELECT * FROM app_access_logs
     WHERE ${conditions.join(' AND ')}
     ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...values, limit, offset]
  );
  return rows;
}

// ─── IP Allowlist ─────────────────────────────────────────────

async function listIpAllowlist() {
  const [rows] = await pool.query('SELECT * FROM admin_ip_allowlist ORDER BY created_at DESC');
  return rows;
}

async function addIpAllowlist({ ip, label, addedBy }) {
  const [result] = await pool.query(
    'INSERT INTO admin_ip_allowlist (ip, label, added_by) VALUES (?, ?, ?)',
    [ip, label ?? null, addedBy ?? null]
  );
  return result.insertId;
}

async function updateIpAllowlist(id, { label, is_active }) {
  const fields = [];
  const values = [];
  if (label     !== undefined) { fields.push('label = ?');     values.push(label); }
  if (is_active !== undefined) { fields.push('is_active = ?'); values.push(is_active ? 1 : 0); }
  if (!fields.length) return;
  values.push(id);
  await pool.query(`UPDATE admin_ip_allowlist SET ${fields.join(', ')} WHERE id = ?`, values);
}

async function removeIpAllowlist(id) {
  await pool.query('DELETE FROM admin_ip_allowlist WHERE id = ?', [id]);
}

async function getActiveIpAllowlist() {
  const [rows] = await pool.query('SELECT ip FROM admin_ip_allowlist WHERE is_active = 1');
  return rows.map(r => r.ip);
}

// ─── RBAC Menus ──────────────────────────────────────────────

async function listMenus() {
  const [rows] = await pool.query(
    'SELECT * FROM admin_menus ORDER BY sort_order ASC'
  );
  return rows;
}

async function getAccessibleMenus(role) {
  const level = roleLevel(role);
  const [rows] = await pool.query('SELECT * FROM admin_menus ORDER BY sort_order ASC');
  return rows.filter(m => roleLevel(m.min_role) <= level);
}

async function updateMenuRole(menuKey, minRole) {
  await pool.query(
    'UPDATE admin_menus SET min_role = ? WHERE menu_key = ?',
    [minRole, menuKey]
  );
}

module.exports = {
  roleLevel,
  getAdminByUsername, getAdminById, getAdminByIdFull, listAdmins,
  createAdmin, updateAdmin, deleteAdmin,
  updateAdminLastLogin, verifyAdminPassword,
  saveTotpSecret, clearTotpSecret,
  listApps, listActiveApps, createApp, updateApp, deleteApp,
  listProviderUsers, getProviderUserApps, setUserAppAccess, resetUserAppAccess, deleteProviderUser,
  listPositions, getPositionApps, setPositionAppAccess, resetPositionAppAccess,
  listMenus, getAccessibleMenus, updateMenuRole,
  getAdminStats,
  getLoginLogs,
  addAuditLog, getAuditLogs,
  addAppAccessLog, getAppAccessLogs,
  listIpAllowlist, addIpAllowlist, updateIpAllowlist, removeIpAllowlist, getActiveIpAllowlist,
};
