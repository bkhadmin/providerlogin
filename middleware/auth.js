'use strict';

const { verifyToken } = require('../utils/jwt');
const config = require('../config/config');
const { auditLog } = require('./audit');

/**
 * Middleware to protect routes - verifies JWT from httpOnly cookie
 */
function requireAuth(req, res, next) {
  const token = req.cookies?.[config.jwt.cookieName];
  if (!token) {
    auditLog('AUTH_FAILED_NO_TOKEN', req);
    return res.status(401).json({ success: false, message: 'Authentication required.' });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    auditLog('AUTH_FAILED_INVALID_TOKEN', req, { error: err.message });
    // Clear the bad cookie
    res.clearCookie(config.jwt.cookieName);
    return res.status(401).json({ success: false, message: 'Session expired or invalid. Please login again.' });
  }
}

module.exports = { requireAuth };
