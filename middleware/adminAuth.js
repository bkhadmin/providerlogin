'use strict';

const jwt     = require('jsonwebtoken');
const config  = require('../config/config');
const { roleLevel } = require('../database/adminModel');

const ADMIN_COOKIE    = 'admin_session';
const PENDING_COOKIE  = 'admin_2fa_pending';

function signAdminToken(payload) {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: '8h',
    issuer:    'providerlogin-admin',
  });
}

function verifyAdminToken(token) {
  return jwt.verify(token, config.jwt.secret, {
    issuer: 'providerlogin-admin',
  });
}

/** JWT สำหรับ pending 2FA (อายุ 5 นาที) */
function signPendingToken(adminId) {
  return jwt.sign({ adminId, step: '2fa-pending' }, config.jwt.secret, {
    expiresIn: '5m',
    issuer:    'providerlogin-admin',
  });
}

function verifyPendingToken(token) {
  const decoded = jwt.verify(token, config.jwt.secret, { issuer: 'providerlogin-admin' });
  if (decoded.step !== '2fa-pending') throw new Error('invalid_step');
  return decoded;
}

/** Middleware: ตรวจสอบ admin session cookie */
function requireAdminAuth(req, res, next) {
  const token = req.cookies?.[ADMIN_COOKIE];
  if (!token) {
    return res.status(401).json({ success: false, message: 'Admin authentication required.' });
  }
  try {
    req.admin = verifyAdminToken(token);
    next();
  } catch {
    res.clearCookie(ADMIN_COOKIE);
    return res.status(401).json({ success: false, message: 'Admin session expired.' });
  }
}

/** Middleware factory: ตรวจสอบ role ขั้นต่ำ */
function requireRole(minRole) {
  return (req, res, next) => {
    if (roleLevel(req.admin?.role) >= roleLevel(minRole)) {
      return next();
    }
    return res.status(403).json({ success: false, message: 'Access denied. Insufficient role.' });
  };
}

module.exports = {
  signAdminToken, verifyAdminToken,
  signPendingToken, verifyPendingToken,
  requireAdminAuth, requireRole,
  ADMIN_COOKIE, PENDING_COOKIE,
};
