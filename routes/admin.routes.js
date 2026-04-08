'use strict';

const { Router } = require('express');
const {
  requireAdminAuth, requireRole,
  signAdminToken, signPendingToken, verifyPendingToken,
  ADMIN_COOKIE, PENDING_COOKIE,
} = require('../middleware/adminAuth');
const { authLimiter } = require('../middleware/security');
const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');
const m = require('../database/adminModel');
const { invalidateCache: invalidateIpCache } = require('../middleware/ipAllowlist');

const router = Router();
const isProd = process.env.NODE_ENV === 'production';

// ─── Auth ─────────────────────────────────────────────────────

router.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body ?? {};
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'กรุณากรอก username และ password' });
    }
    const admin = await m.getAdminByUsername(username).catch(() => null);
    if (!admin || !(await m.verifyAdminPassword(admin, password))) {
      return res.status(401).json({ success: false, message: 'username หรือ password ไม่ถูกต้อง' });
    }

    // superadmin + มี totp_secret → ต้องยืนยัน 2FA ก่อน
    if (admin.role === 'superadmin' && admin.totp_secret) {
      const pendingToken = signPendingToken(admin.id);
      res.cookie(PENDING_COOKIE, pendingToken, {
        httpOnly: true,
        secure:   isProd,
        sameSite: 'Strict',
        maxAge:   5 * 60 * 1000,
      });
      return res.json({ success: true, requires_2fa: true });
    }

    // login ปกติ (non-superadmin หรือยังไม่ได้ setup 2FA)
    await m.updateAdminLastLogin(admin.id);
    const token = signAdminToken({ adminId: admin.id, username: admin.username, role: admin.role, displayName: admin.display_name });
    res.cookie(ADMIN_COOKIE, token, {
      httpOnly: true,
      secure:   isProd,
      sameSite: 'Strict',
      maxAge:   8 * 60 * 60 * 1000,
    });
    res.json({ success: true, requires_2fa: false, role: admin.role, displayName: admin.display_name });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── ยืนยัน OTP หลัง login ──────────────────────────────────────
router.post('/auth/2fa/verify', authLimiter, async (req, res) => {
  try {
    const pendingToken = req.cookies?.[PENDING_COOKIE];
    if (!pendingToken) {
      return res.status(401).json({ success: false, message: 'ไม่พบ pending session กรุณา login ใหม่' });
    }

    let decoded;
    try {
      decoded = verifyPendingToken(pendingToken);
    } catch {
      res.clearCookie(PENDING_COOKIE);
      return res.status(401).json({ success: false, message: 'Session หมดอายุ กรุณา login ใหม่' });
    }

    const { code } = req.body ?? {};
    if (!code) {
      return res.status(400).json({ success: false, message: 'กรุณากรอกรหัส OTP' });
    }

    const admin = await m.getAdminByIdFull(decoded.adminId);
    if (!admin || !admin.totp_secret) {
      res.clearCookie(PENDING_COOKIE);
      return res.status(401).json({ success: false, message: 'ไม่พบข้อมูล 2FA' });
    }

    const valid = speakeasy.totp.verify({
      secret:   admin.totp_secret,
      encoding: 'base32',
      token:    String(code).replace(/\s/g, ''),
      window:   1,
    });

    if (!valid) {
      return res.status(401).json({ success: false, message: 'รหัส OTP ไม่ถูกต้อง' });
    }

    res.clearCookie(PENDING_COOKIE);
    await m.updateAdminLastLogin(admin.id);
    const token = signAdminToken({ adminId: admin.id, username: admin.username, role: admin.role, displayName: admin.display_name });
    res.cookie(ADMIN_COOKIE, token, {
      httpOnly: true,
      secure:   isProd,
      sameSite: 'Strict',
      maxAge:   8 * 60 * 60 * 1000,
    });
    res.json({ success: true, role: admin.role, displayName: admin.display_name });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── Setup 2FA: สร้าง secret + QR ────────────────────────────────
router.get('/auth/2fa/setup', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ name: `ProviderPortal (${req.admin.username})`, length: 20 });
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ success: true, secret: secret.base32, qr: qrDataUrl });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── Confirm 2FA: ยืนยัน OTP แล้ว save secret ────────────────────
router.post('/auth/2fa/setup', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { secret, code } = req.body ?? {};
    if (!secret || !code) {
      return res.status(400).json({ success: false, message: 'ข้อมูลไม่ครบ' });
    }
    const valid = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token:    String(code).replace(/\s/g, ''),
      window:   1,
    });
    if (!valid) {
      return res.status(400).json({ success: false, message: 'รหัส OTP ไม่ถูกต้อง กรุณาลองใหม่' });
    }
    await m.saveTotpSecret(req.admin.adminId, secret);
    res.json({ success: true, message: 'เปิดใช้งาน 2FA เรียบร้อยแล้ว' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── Disable 2FA ──────────────────────────────────────────────────
router.delete('/auth/2fa/setup', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { code } = req.body ?? {};
    const admin = await m.getAdminByIdFull(req.admin.adminId);
    if (admin?.totp_secret) {
      const valid = speakeasy.totp.verify({
        secret:   admin.totp_secret,
        encoding: 'base32',
        token:    String(code ?? '').replace(/\s/g, ''),
        window:   1,
      });
      if (!valid) {
        return res.status(400).json({ success: false, message: 'รหัส OTP ไม่ถูกต้อง' });
      }
    }
    await m.clearTotpSecret(req.admin.adminId);
    res.json({ success: true, message: 'ปิดใช้งาน 2FA เรียบร้อยแล้ว' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── ตรวจสอบสถานะ 2FA ─────────────────────────────────────────────
router.get('/auth/2fa/status', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const admin = await m.getAdminByIdFull(req.admin.adminId);
    res.json({ success: true, enabled: !!admin?.totp_secret });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

router.post('/auth/logout', requireAdminAuth, (req, res) => {
  res.clearCookie(ADMIN_COOKIE);
  res.json({ success: true });
});

router.get('/auth/me', requireAdminAuth, (req, res) => {
  res.json({ success: true, data: req.admin });
});

// ─── Menus (RBAC) ─────────────────────────────────────────────

/** คืน menus ที่ admin คนนี้เข้าถึงได้ */
router.get('/menus', requireAdminAuth, async (req, res) => {
  const menus = await m.getAccessibleMenus(req.admin.role);
  res.json({ success: true, data: menus });
});

/** superadmin: ดู/แก้ไข min_role ของ menu */
router.get('/rbac', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  const menus = await m.listMenus();
  res.json({ success: true, data: menus });
});

router.put('/rbac/:menuKey', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  const { menuKey } = req.params;
  const { min_role } = req.body ?? {};
  const validRoles = ['superadmin', 'admin1', 'admin2', 'user'];
  if (!validRoles.includes(min_role)) {
    return res.status(400).json({ success: false, message: 'Invalid role' });
  }
  await m.updateMenuRole(menuKey, min_role);
  res.json({ success: true });
});

// ─── Applications ─────────────────────────────────────────────

router.get('/apps', requireAdminAuth, requireRole('admin2'), async (req, res) => {
  const apps = await m.listApps();
  res.json({ success: true, data: apps });
});

router.post('/apps', requireAdminAuth, requireRole('admin2'), async (req, res) => {
  const { app_id, name, description, icon, url, required_expertise, hcode_whitelist, sort_order } = req.body ?? {};
  if (!app_id || !name || !url) {
    return res.status(400).json({ success: false, message: 'app_id, name และ url จำเป็นต้องกรอก' });
  }
  try {
    const id = await m.createApp({ app_id, name, description, icon, url, required_expertise, hcode_whitelist, sort_order });
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'CREATE_APP', targetType: 'app', targetId: app_id, detail: { name, url }, ip: req.ip });
    res.status(201).json({ success: true, id });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'app_id นี้มีในระบบแล้ว' });
    }
    throw e;
  }
});

router.put('/apps/:id', requireAdminAuth, requireRole('admin2'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    await m.updateApp(id, req.body ?? {});
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'UPDATE_APP', targetType: 'app', targetId: String(id), detail: req.body, ip: req.ip });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

router.delete('/apps/:id', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await m.deleteApp(id);
  await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
    action: 'DELETE_APP', targetType: 'app', targetId: String(id), detail: null, ip: req.ip });
  res.json({ success: true });
});

// ─── Admin Accounts ───────────────────────────────────────────

router.get('/admins', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  const admins = await m.listAdmins();
  res.json({ success: true, data: admins });
});

router.post('/admins', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  const { username, password, display_name, role } = req.body ?? {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'username และ password จำเป็นต้องกรอก' });
  }
  if (password.length < 8) {
    return res.status(400).json({ success: false, message: 'password ต้องมีอย่างน้อย 8 ตัวอักษร' });
  }
  try {
    const id = await m.createAdmin({ username, password, display_name, role });
    res.status(201).json({ success: true, id });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Username นี้มีในระบบแล้ว' });
    }
    throw e;
  }
});

router.put('/admins/:id', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { display_name, role, is_active, password } = req.body ?? {};

  // admin1 ไม่สามารถเปลี่ยน role ได้ (superadmin เท่านั้น)
  if (role !== undefined && m.roleLevel(req.admin.role) < m.roleLevel('superadmin')) {
    return res.status(403).json({ success: false, message: 'เฉพาะ superadmin เท่านั้นที่เปลี่ยน role ได้' });
  }
  // ห้ามแก้ไขตัวเอง (ป้องกัน lock ตัวเอง)
  if (targetId === req.admin.adminId && is_active === false) {
    return res.status(400).json({ success: false, message: 'ไม่สามารถปิดบัญชีตัวเองได้' });
  }
  await m.updateAdmin(targetId, { display_name, role, is_active, password });
  res.json({ success: true });
});

router.delete('/admins/:id', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.admin.adminId) {
    return res.status(400).json({ success: false, message: 'ไม่สามารถลบบัญชีตัวเองได้' });
  }
  await m.deleteAdmin(targetId);
  res.json({ success: true });
});

// ─── Provider Users ───────────────────────────────────────────

router.get('/users', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  const users = await m.listProviderUsers();
  res.json({ success: true, data: users });
});

router.get('/users/:id/apps', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  const apps = await m.getProviderUserApps(parseInt(req.params.id, 10));
  res.json({ success: true, data: apps });
});

router.put('/users/:id/apps/:appId', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    const { is_allowed } = req.body ?? {};
    await m.setUserAppAccess(userId, req.params.appId, is_allowed, req.admin.adminId);
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'SET_USER_APP_ACCESS', targetType: 'user', targetId: String(userId),
      detail: { app_id: req.params.appId, is_allowed }, ip: req.ip });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// รีเซ็ต override รายคน (กลับไปใช้ตามตำแหน่ง/default)
router.delete('/users/:id/apps/:appId', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    await m.resetUserAppAccess(parseInt(req.params.id, 10), req.params.appId);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.delete('/users/:id', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    await m.deleteProviderUser(parseInt(req.params.id, 10));
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── Position App Access ───────────────────────────────────────

router.get('/positions', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const rows = await m.listPositions();
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.get('/positions/:position/apps', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const apps = await m.getPositionApps(req.params.position);
    res.json({ success: true, data: apps });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.put('/positions/:position/apps/:appId', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { is_allowed } = req.body ?? {};
    await m.setPositionAppAccess(req.params.position, req.params.appId, is_allowed, req.admin.adminId);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.delete('/positions/:position/apps/:appId', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    await m.resetPositionAppAccess(req.params.position, req.params.appId);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Batch: grant all / revoke all
router.post('/positions/:position/apps/grant-all', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { is_allowed } = req.body ?? {};
    await m.grantAllPositionApps(req.params.position, is_allowed !== false, req.admin.adminId);
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: is_allowed !== false ? 'POSITION_GRANT_ALL' : 'POSITION_REVOKE_ALL',
      targetType: 'position', targetId: req.params.position, ip: req.ip });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Batch: reset all (คืนค่า default ทั้งหมด)
router.post('/positions/:position/apps/reset-all', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    await m.resetAllPositionAppAccess(req.params.position);
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'POSITION_RESET_ALL', targetType: 'position', targetId: req.params.position, ip: req.ip });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Batch: copy from another position
router.post('/positions/:position/apps/copy-from', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { from_position } = req.body ?? {};
    if (!from_position) return res.status(400).json({ success: false, message: 'from_position required' });
    await m.copyPositionAppAccess(from_position, req.params.position, req.admin.adminId);
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'POSITION_COPY_FROM', targetType: 'position', targetId: req.params.position,
      detail: { from: from_position }, ip: req.ip });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Batch: set หลาย app พร้อมกัน
router.post('/positions/:position/apps/batch', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { apps } = req.body ?? {};
    if (!Array.isArray(apps) || !apps.length) return res.status(400).json({ success: false, message: 'apps array required' });
    await m.batchSetPositionAppAccess(req.params.position, apps, req.admin.adminId);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── Dashboard Stats ──────────────────────────────────────────

router.get('/stats', requireAdminAuth, requireRole('admin2'), async (req, res) => {
  try {
    const stats = await m.getAdminStats();
    res.json({ success: true, data: stats });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── Login Logs ───────────────────────────────────────────────

router.get('/logs/login', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { limit = 100, offset = 0, event, days = 7 } = req.query;
    const rows = await m.getLoginLogs({
      limit:  Math.min(parseInt(limit, 10) || 100, 500),
      offset: parseInt(offset, 10) || 0,
      event:  event || null,
      days:   parseInt(days, 10) || 7,
    });
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── Admin Audit Logs ─────────────────────────────────────────

router.get('/logs/audit', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { limit = 100, offset = 0, days = 30 } = req.query;
    const rows = await m.getAuditLogs({
      limit:  Math.min(parseInt(limit, 10) || 100, 500),
      offset: parseInt(offset, 10) || 0,
      days:   parseInt(days, 10) || 30,
    });
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── App Usage Logs ───────────────────────────────────────────

router.get('/logs/app', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { limit = 500, offset = 0, app_id, date_from, date_to } = req.query;
    const today = new Date().toISOString().slice(0, 10);
    const rows = await m.getAppAccessLogs({
      limit:    Math.min(parseInt(limit, 10) || 500, 1000),
      offset:   parseInt(offset, 10) || 0,
      appId:    app_id || null,
      dateFrom: date_from || today,
      dateTo:   date_to   || today,
    });
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.get('/logs/app/summary', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const { app_id, date_from, date_to } = req.query;
    const today = new Date().toISOString().slice(0, 10);
    const summary = await m.getAppAccessSummary({
      appId:    app_id    || null,
      dateFrom: date_from || today,
      dateTo:   date_to   || today,
    });
    res.json({ success: true, data: summary });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// คืนรายชื่อ app ทั้งหมดที่มีใน access logs (สำหรับ dropdown filter)
router.get('/logs/app/apps', requireAdminAuth, requireRole('admin1'), async (req, res) => {
  try {
    const [rows] = await require('../database/db').pool.query(
      'SELECT DISTINCT app_id, app_name FROM app_access_logs ORDER BY app_name ASC'
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── IP Allowlist ─────────────────────────────────────────────

router.get('/ip-allowlist', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const rows = await m.listIpAllowlist();
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.post('/ip-allowlist', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { ip, label } = req.body ?? {};
    if (!ip) return res.status(400).json({ success: false, message: 'IP จำเป็นต้องกรอก' });
    // validate IP/CIDR format basic check
    if (!/^[\d.:a-fA-F/]+$/.test(ip)) {
      return res.status(400).json({ success: false, message: 'รูปแบบ IP ไม่ถูกต้อง' });
    }
    const id = await m.addIpAllowlist({ ip, label, addedBy: req.admin.adminId });
    invalidateIpCache();
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'ADD_IP_ALLOWLIST', targetType: 'ip', targetId: ip,
      detail: { label }, ip: req.ip });
    res.status(201).json({ success: true, id });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ success: false, message: 'IP นี้มีในระบบแล้ว' });
    res.status(500).json({ success: false, message: e.message });
  }
});

router.put('/ip-allowlist/:id', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { label, is_active } = req.body ?? {};
    await m.updateIpAllowlist(id, { label, is_active });
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'UPDATE_IP_ALLOWLIST', targetType: 'ip', targetId: String(id),
      detail: { label, is_active }, ip: req.ip });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

router.delete('/ip-allowlist/:id', requireAdminAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    await m.removeIpAllowlist(id);
    invalidateIpCache();
    await m.addAuditLog({ adminId: req.admin.adminId, username: req.admin.username, role: req.admin.role,
      action: 'REMOVE_IP_ALLOWLIST', targetType: 'ip', targetId: String(id),
      detail: null, ip: req.ip });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

module.exports = router;
