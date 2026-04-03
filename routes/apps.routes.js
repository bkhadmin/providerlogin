'use strict';

const { Router } = require('express');
const { requireAuth } = require('../middleware/auth');
const { listActiveApps, addAppAccessLog } = require('../database/adminModel');
const { pool } = require('../database/db');

const router = Router();

/**
 * GET /api/apps
 * คืนรายการ app ที่ user เข้าถึงได้ โดยกรองจาก:
 * 1. is_active = 1
 * 2. required_expertise ตรงกับ user (ถ้ามี)
 * 3. hcode_whitelist ตรงกับ hcode ของ user (ถ้ากำหนด)
 * 4. user_app_access override (ถ้า admin ตั้งค่าไว้)
 */
router.get('/', requireAuth, async (req, res) => {
  const allApps        = await listActiveApps();
  const userExpertises = (req.user.organizations || []).map(o => o.expertise).filter(Boolean);
  const userHcodes     = (req.user.organizations || []).map(o => o.hcode).filter(Boolean);
  const userPositions  = (req.user.organizations || []).map(o => o.position).filter(Boolean);

  // ดึง individual override ของ user นี้
  const [accessRows] = await pool.query(
    `SELECT uaa.app_id, uaa.is_allowed
     FROM user_app_access uaa
     JOIN users u ON u.id = uaa.user_id
     WHERE u.account_id = ?`,
    [req.user.accountId]
  );
  const accessMap = Object.fromEntries(accessRows.map(r => [r.app_id, r.is_allowed]));

  // ดึง position rules ของ user (ทุก position ที่ user มี)
  // positionMap[app_id] = true ถ้า any position อนุญาต, false ถ้าทุก position ที่มี rule ปิดกั้น
  const positionMap = {};
  if (userPositions.length) {
    const placeholders = userPositions.map(() => '?').join(',');
    const [posRows] = await pool.query(
      `SELECT app_id, MAX(is_allowed) AS is_allowed
       FROM position_app_access
       WHERE position IN (${placeholders})
       GROUP BY app_id`,
      userPositions
    );
    posRows.forEach(r => { positionMap[r.app_id] = r.is_allowed === 1; });
  }

  const accessibleApps = allApps
    .filter(app => {
      // 1. Individual override — สิทธิ์สูงสุด
      if (app.app_id in accessMap) return accessMap[app.app_id] === 1;

      // 2. Position rule — ถ้ามี rule สำหรับ app นี้
      if (app.app_id in positionMap) return positionMap[app.app_id];

      // 3. hcode_whitelist
      if (app.hcode_whitelist) {
        try {
          const allowed = JSON.parse(app.hcode_whitelist);
          if (Array.isArray(allowed) && allowed.length > 0) {
            if (!userHcodes.some(h => allowed.includes(h))) return false;
          }
        } catch { /* ignore parse error */ }
      }

      // 4. required_expertise
      if (!app.required_expertise) return true;
      return userExpertises.includes(app.required_expertise);
    })
    .map(({ id, created_at, updated_at, ...rest }) => rest);

  res.json({ success: true, data: accessibleApps });
});

/**
 * GET /api/apps/:appId/token
 * ออก SSO token อายุ 15 นาทีสำหรับ app นั้น + บันทึก app_access_logs
 */
router.get('/:appId/token', requireAuth, async (req, res) => {
  const { appId } = req.params;
  const jwt    = require('jsonwebtoken');
  const config = require('../config/config');

  // ตรวจว่า app มีอยู่และ active
  const [appRows] = await pool.query(
    'SELECT app_id, name FROM applications WHERE app_id = ? AND is_active = 1',
    [appId]
  );
  if (!appRows.length) {
    return res.status(404).json({ success: false, message: 'App not found or inactive.' });
  }
  const appInfo = appRows[0];

  const u      = req.user;
  const org    = (u.organizations && u.organizations[0]) || {};
  // Strip duplicate title prefix from firstname (e.g. firstnameTh="นายวีรวัฒน์" when titleTh="นาย")
  const _titles = ['นางสาว', 'นาง', 'นาย', 'เด็กชาย', 'เด็กหญิง', 'ด.ช.', 'ด.ญ.'];
  let _fn = (u.firstnameTh ?? '').trim();
  for (const _t of _titles) { if (_fn.startsWith(_t)) { _fn = _fn.slice(_t.length).trim(); break; } }
  const nameTh = [(u.titleTh ?? '').trim(), _fn, (u.lastnameTh ?? '').trim()].filter(Boolean).join(' ');

  const appToken = jwt.sign(
    {
      sub:         u.accountId,
      username:    u.username,
      providerId:  u.providerId,
      nameTh,
      titleTh:     (u.titleTh     ?? '').trim(),
      firstnameTh: _fn,
      lastnameTh:  (u.lastnameTh  ?? '').trim(),
      nameEng:     [(u.firstnameEn ?? '').trim(), (u.lastnameEn ?? '').trim()].filter(Boolean).join(' '),
      titleEn:     (u.titleEn     ?? '').trim(),
      hcode:       org.hcode    ?? '',
      hnameTh:     org.hnameTh  ?? '',
      position:    org.position ?? '',
      appId,
      scope:       'app-access',
    },
    config.jwt.secret,
    { expiresIn: '15m', issuer: 'providerlogin', audience: 'web-apps' }
  );

  // บันทึก usage log (non-blocking)
  addAppAccessLog({
    userId:    u.dbUserId ?? null,
    accountId: u.accountId,
    username:  u.username,
    appId,
    appName:   appInfo.name,
    ip:        req.ip,
    userAgent: req.headers['user-agent'],
  }).catch(() => {});

  res.json({ success: true, token: appToken, expiresIn: 900 });
});

/**
 * GET /api/apps/:appId/launch
 * ออก SSO token แล้ว redirect ไปยัง app URL พร้อม ?sso_token=...
 * ใช้สำหรับปุ่ม login จากภายนอก (ไม่ต้องผ่าน dashboard JS)
 */
router.get('/:appId/launch', requireAuth, async (req, res) => {
  const { appId } = req.params;
  const jwt    = require('jsonwebtoken');
  const config = require('../config/config');

  const [appRows] = await pool.query(
    'SELECT app_id, name, url FROM applications WHERE app_id = ? AND is_active = 1',
    [appId]
  );
  if (!appRows.length) {
    return res.status(404).json({ success: false, message: 'App not found or inactive.' });
  }
  const appInfo = appRows[0];

  const u   = req.user;
  const org = (u.organizations && u.organizations[0]) || {};
  const _titles = ['นางสาว', 'นาง', 'นาย', 'เด็กชาย', 'เด็กหญิง', 'ด.ช.', 'ด.ญ.'];
  let _fn = (u.firstnameTh ?? '').trim();
  for (const _t of _titles) { if (_fn.startsWith(_t)) { _fn = _fn.slice(_t.length).trim(); break; } }
  const nameTh = [(u.titleTh ?? '').trim(), _fn, (u.lastnameTh ?? '').trim()].filter(Boolean).join(' ');

  const appToken = jwt.sign(
    {
      sub:         u.accountId,
      username:    u.username,
      providerId:  u.providerId,
      nameTh,
      titleTh:     (u.titleTh     ?? '').trim(),
      firstnameTh: _fn,
      lastnameTh:  (u.lastnameTh  ?? '').trim(),
      nameEng:     [(u.firstnameEn ?? '').trim(), (u.lastnameEn ?? '').trim()].filter(Boolean).join(' '),
      titleEn:     (u.titleEn     ?? '').trim(),
      hcode:       org.hcode    ?? '',
      hnameTh:     org.hnameTh  ?? '',
      position:    org.position ?? '',
      appId,
      scope:       'app-access',
    },
    config.jwt.secret,
    { expiresIn: '15m', issuer: 'providerlogin', audience: 'web-apps' }
  );

  addAppAccessLog({
    userId:    u.dbUserId ?? null,
    accountId: u.accountId,
    username:  u.username,
    appId,
    appName:   appInfo.name,
    ip:        req.ip,
    userAgent: req.headers['user-agent'],
  }).catch(() => {});

  // redirect ไปยัง app URL พร้อม token
  const appUrl = (appInfo.url || '').replace(/\/$/, '');
  const sep    = appUrl.includes('?') ? '&' : '?';
  return res.redirect(`${appUrl}${sep}sso_token=${appToken}`);
});

module.exports = router;
