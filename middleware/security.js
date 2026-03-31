'use strict';

const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const config = require('../config/config');

// ─── Helmet Security Headers ──────────────────────────────────────────────────
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],       // allow onclick handlers
      styleSrc:      ["'self'", "'unsafe-inline'"],
      fontSrc:       ["'self'", 'data:'],
      imgSrc:        ["'self'", 'data:'],
      connectSrc:    ["'self'"],
      frameSrc:      ["'none'"],
      objectSrc:     ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,          // 1 year
    includeSubDomains: true,
    preload: true,
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
});

// ─── CORS ─────────────────────────────────────────────────────────────────────
const corsMiddleware = cors({
  origin(origin, callback) {
    // Allow no-origin (same-origin requests, curl, etc.) or whitelisted origins
    if (!origin || config.allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS: Origin "${origin}" not allowed`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
  maxAge: 600,
});

// ─── Global Rate Limit ────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests, please try again later.' },
});

// ─── Strict Rate Limit for Auth Endpoints ────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.authMax,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: { success: false, message: 'Too many login attempts. Please wait 15 minutes.' },
});

// ─── HTTP Parameter Pollution Prevention ─────────────────────────────────────
const hppMiddleware = hpp();

// ─── CSRF Token (Double-Submit Cookie) ──────────────────────────────────────
const { v4: uuidv4 } = require('uuid');

function csrfProtect(req, res, next) {
  // Skip GET/HEAD/OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const tokenFromCookie = req.cookies?.['csrf_token'];
  const tokenFromHeader = req.headers['x-csrf-token'];

  if (!tokenFromCookie || !tokenFromHeader || tokenFromCookie !== tokenFromHeader) {
    return res.status(403).json({ success: false, message: 'CSRF token mismatch.' });
  }
  next();
}

function setCsrfToken(req, res, next) {
  if (!req.cookies?.['csrf_token']) {
    const token = uuidv4();
    res.cookie('csrf_token', token, {
      httpOnly: false,    // JS must read this to send in header
      sameSite: 'Strict',
      secure: config.isProd,
      maxAge: 8 * 60 * 60 * 1000, // 8 hours
    });
  }
  next();
}

module.exports = {
  helmetMiddleware,
  corsMiddleware,
  globalLimiter,
  authLimiter,
  hppMiddleware,
  csrfProtect,
  setCsrfToken,
};
