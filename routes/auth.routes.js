'use strict';

const { Router } = require('express');
const { authLimiter } = require('../middleware/security');
const { requireAuth } = require('../middleware/auth');
const { csrfProtect } = require('../middleware/security');
const {
  initiateLogin,
  handleCallback,
  logout,
  getProfile,
  getStatus,
} = require('../controllers/auth.controller');

const router = Router();

// Public routes (rate-limited)
router.get('/login', authLimiter, initiateLogin);
// GET /callback kept for legacy; POST /callback is the primary path per SKILL.md
router.get('/callback',  authLimiter, handleCallback);
router.post('/callback', authLimiter, handleCallback);
router.get('/status', getStatus);

// Protected routes (require valid JWT cookie)
router.get('/profile', requireAuth, getProfile);

// Refresh session — ออก JWT ใหม่ถ้า token ยังไม่หมดอายุ (silent refresh)
router.post('/refresh', requireAuth, (req, res) => {
  const jwt    = require('jsonwebtoken');
  const config = require('../config/config');
  const { signToken } = require('../utils/jwt');

  try {
    const token   = req.cookies?.[config.jwt.cookieName];
    const decoded = jwt.decode(token);
    if (!decoded) return res.status(401).json({ success: false, message: 'Invalid token.' });

    // สร้าง payload ใหม่ (ลบ fields ที่ jwt เพิ่มเองออก)
    const { iat, exp, iss, aud, ...payload } = decoded;
    const newToken = signToken(payload);

    res.cookie(config.jwt.cookieName, newToken, {
      httpOnly: true,
      secure:   config.isProd,
      sameSite: 'Lax',
      maxAge:   8 * 60 * 60 * 1000,
    });
    res.json({ success: true, message: 'Session refreshed.' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Logout (requires auth + CSRF)
router.post('/logout', requireAuth, csrfProtect, logout);

module.exports = router;
