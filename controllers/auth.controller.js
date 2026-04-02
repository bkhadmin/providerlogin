'use strict';

const { generateState, generateCodeVerifier, generateCodeChallenge } = require('../utils/crypto');
const { exchangeHealthIdCode, exchangeToken, fetchProfile } = require('../utils/providerApi');
const { signToken } = require('../utils/jwt');
const { auditLog } = require('../middleware/audit');
const { upsertUser, syncOrganizations, recordLoginLog } = require('../database/userModel');
const config = require('../config/config');

// In-memory state store (replace with Redis in production)
const stateStore = new Map();

// Clean up stale states every hour
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of stateStore.entries()) {
    if (now - val.createdAt > 10 * 60 * 1000) stateStore.delete(key); // 10min TTL
  }
}, 60 * 60 * 1000);

/**
 * GET /api/auth/login
 * Initiates OAuth flow - redirects to Health ID
 */
async function initiateLogin(req, res) {
  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // เก็บ returnTo ถ้ามี (เช่น /api/apps/app-bkita/launch)
  const returnTo = req.query.returnTo || null;

  // Store state + verifier indexed by state value (10-minute TTL)
  stateStore.set(state, { codeVerifier, createdAt: Date.now(), returnTo });

  const params = new URLSearchParams({
    client_id:     config.healthId.clientId || 'YOUR_HEALTH_ID_CLIENT_ID',
    redirect_uri:  config.healthId.redirectUri,
    response_type: 'code',
    state,  // เก็บไว้เพื่อป้องกัน CSRF
  });

  const authUrl = `${config.healthId.oauthUrl}/oauth/redirect?${params.toString()}`;
  auditLog('LOGIN_INITIATED', req, { state });
  res.redirect(authUrl);
}

/**
 * GET /api/auth/callback
 * Handles OAuth callback from Health ID
 * Exchanges code → health_id_token → provider_token → issues session JWT
 */
async function handleCallback(req, res) {
  // รับ code+state จาก POST body (SKILL pattern) หรือ query string (fallback)
  const isPost  = req.method === 'POST';
  const code    = req.body?.code  || req.query.code;
  const state   = req.body?.state || req.query.state;
  const error   = req.body?.error || req.query.error;

  // helper: ส่ง error กลับ (JSON สำหรับ POST, redirect สำหรับ GET)
  function sendError(msg) {
    if (isPost) return res.status(400).json({ success: false, error: msg });
    return res.redirect('/?error=' + msg);
  }

  // Handle OAuth errors from Health ID
  if (error) {
    auditLog('LOGIN_OAUTH_ERROR', req, { error });
    return sendError(encodeURIComponent(error));
  }

  // Validate state to prevent CSRF
  const storedState = stateStore.get(state);
  if (!state || !storedState) {
    auditLog('LOGIN_INVALID_STATE', req, { state });
    return sendError('invalid_state');
  }
  const returnTo = storedState.returnTo || null;
  stateStore.delete(state); // Consume state immediately

  // Validate code
  if (!code) {
    auditLog('LOGIN_NO_CODE', req);
    return sendError('no_code');
  }

  try {
    console.log('[STEP 2] Exchanging code for Health ID token...');
    const healthIdData = await exchangeHealthIdCode(code);
    const healthIdToken = healthIdData.access_token;
    console.log('[STEP 2] OK - got health_id_access_token');

    console.log('[STEP 3] Exchanging Health ID token for Provider ID token...');
    const providerTokenData = await exchangeToken(healthIdToken);
    console.log('[STEP 3] OK - got provider_access_token, username:', providerTokenData.username);

    console.log('[STEP 4] Fetching Provider Profile...');
    const profile = await fetchProfile(providerTokenData.access_token);
    console.log('[STEP 4] OK - got profile, provider_id:', profile.provider_id);


    // ── Step 4: Save/Update all Provider data to MySQL ───────────────────────
    // Merge account_id and username from token data into profile
    const profileFull = {
      ...profile,
      account_id: providerTokenData.account_id,
      username:   providerTokenData.username,
    };

    // Upsert user record (INSERT or UPDATE)
    const userId = await upsertUser(profileFull);

    // Sync organizations (replace all existing with fresh data)
    await syncOrganizations(userId, profile.organization || []);

    // Record successful login log
    await recordLoginLog({
      userId,
      accountId: providerTokenData.account_id,
      username:  providerTokenData.username,
      ip:        req.ip,
      userAgent: req.headers['user-agent'],
      event:     'LOGIN_SUCCESS',
    });
    // ─────────────────────────────────────────────────────────────────────────

    // Step 5: Build session JWT payload (only non-sensitive fields)
    const sessionPayload = {
      accountId: providerTokenData.account_id,
      username: providerTokenData.username,
      providerId: profile.provider_id,
      hashCid: profile.hash_cid,
      titleTh: profile.title_th,
      firstnameTh: profile.firstname_th,
      lastnameTh: profile.lastname_th,
      titleEn: profile.title_en,
      firstnameEn: profile.firstname_en,
      lastnameEn: profile.lastname_en,
      organizations: (profile.organization || []).map(org => ({
        hcode: org.hcode,
        hnameTh: org.hname_th,
        position: org.position,
        expertise: org.expertise,
        isHrAdmin: org.is_hr_admin,
        isDirector: org.is_director,
      })),
      loginAt: new Date().toISOString(),
    };

    const sessionToken = signToken(sessionPayload);

    // Step 6: Set secure httpOnly cookie
    const cookieOptions = {
      httpOnly: true,
      secure: config.isProd,
      sameSite: 'Strict',
      maxAge: 8 * 60 * 60 * 1000, // 8 hours
    };
    res.cookie(config.jwt.cookieName, sessionToken, cookieOptions);

    auditLog('LOGIN_SUCCESS', req, {
      username: providerTokenData.username,
      accountId: providerTokenData.account_id,
    });

    // POST: ส่ง JSON กลับให้ frontend redirect เอง / GET: redirect โดยตรง
    const postLoginRedirect = returnTo || '/dashboard.html';
    if (isPost) {
      return res.json({ success: true, redirect: postLoginRedirect });
    }
    res.redirect(postLoginRedirect);
  } catch (err) {
    // ── ดู error จริงๆ ใน terminal ──────────────────────────────────────────
    // ── DEBUG: แสดง error ตรงใน terminal ────────────────────────────────────
    console.error('=== LOGIN FAILED ===');
    console.error('Error message :', err.message);
    console.error('Failed URL    :', err.config?.url);
    console.error('HTTP Status   :', err.response?.status);
    console.error('Response body :', JSON.stringify(err.response?.data)?.slice(0, 500));
    console.error('===================');
    // ─────────────────────────────────────────────────────────────────────────

    auditLog('LOGIN_FAILURE', req, { error: err.message });

    // Determine event type and user-facing error message
    let msg = 'login_failed';
    let dbEvent = 'LOGIN_FAILURE';
    if (err.response?.status === 400) { msg = 'no_provider_id'; dbEvent = 'LOGIN_NO_PROVIDER_ID'; }
    else if (err.response?.status === 401) { msg = 'unauthorized'; dbEvent = 'LOGIN_UNAUTHORIZED'; }

    // Record failed login (best-effort, do not throw if this fails)
    recordLoginLog({
      userId:    null,
      accountId: null,
      username:  null,
      ip:        req.ip,
      userAgent: req.headers['user-agent'],
      event:     dbEvent,
      errorMsg:  err.message,
    }).catch(() => {});

    if (isPost) {
      return res.status(400).json({ success: false, error: msg });
    }
    res.redirect('/?error=' + msg);
  }
}

/**
 * POST /api/auth/logout
 * Clear session cookie
 */
function logout(req, res) {
  auditLog('LOGOUT', req, { username: req.user?.username });

  // Record logout to DB (best-effort)
  recordLoginLog({
    userId:    null, // ไม่ต้องการ join หาจาก accountId ใน JWT
    accountId: req.user?.accountId,
    username:  req.user?.username,
    ip:        req.ip,
    userAgent: req.headers['user-agent'],
    event:     'LOGOUT',
  }).catch(() => {});

  res.clearCookie(config.jwt.cookieName, { path: '/' });
  res.json({ success: true, message: 'Logged out successfully.' });
}

/**
 * GET /api/auth/profile
 * Return current user profile from JWT (protected)
 */
function getProfile(req, res) {
  res.json({ success: true, data: req.user });
}

/**
 * GET /api/auth/status
 * Check if user is currently authenticated
 */
function getStatus(req, res) {
  const token = req.cookies?.[config.jwt.cookieName];
  if (!token) return res.json({ authenticated: false });

  try {
    const { verifyToken } = require('../utils/jwt');
    const decoded = verifyToken(token);
    return res.json({
      authenticated: true,
      username: decoded.username,
      firstnameTh: decoded.firstnameTh,
      lastnameTh: decoded.lastnameTh,
    });
  } catch {
    return res.json({ authenticated: false });
  }
}

module.exports = { initiateLogin, handleCallback, logout, getProfile, getStatus };
