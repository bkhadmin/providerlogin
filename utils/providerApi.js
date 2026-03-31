'use strict';

const axios = require('axios');
const config = require('../config/config');
const { logger } = require('../middleware/audit');

// ─── Provider ID API client ───────────────────────────────────────────────────
const providerClient = axios.create({
  baseURL: config.providerApi.baseUrl,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Health ID API client ─────────────────────────────────────────────────────
const healthIdClient = axios.create({
  baseURL: config.healthId.oauthUrl,
  timeout: 10000,
});

// Log outgoing requests
[providerClient, healthIdClient].forEach(c => {
  c.interceptors.request.use((req) => {
    logger.info({ event: 'API_REQUEST', method: req.method, url: (req.baseURL || '') + req.url });
    return req;
  });
});

/**
 * Step 2: Exchange Health ID authorization code → access_token
 * POST {HealthID-URL}/api/v1/token  (application/x-www-form-urlencoded)
 * @param {string} code - authorization code from Health ID callback
 * @returns {object} { access_token, token_type, expires_in, account_id }
 */
async function exchangeHealthIdCode(code) {
  // ส่ง credentials ใน body ตามตัวอย่างใน SKILL.md
  const body = new URLSearchParams({
    grant_type:    'authorization_code',
    code,
    redirect_uri:  config.healthId.redirectUri,
    client_id:     config.healthId.clientId,
    client_secret: config.healthId.clientSecret,
  });

  console.log('[HEALTH ID TOKEN] POST', config.healthId.oauthUrl + '/api/v1/token');
  console.log('[HEALTH ID TOKEN] BODY STRING  :', body.toString());  // ← ดู raw body ที่ส่งจริง

  try {
    const response = await healthIdClient.post('/api/v1/token', body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    // Response structure: { "status": "success", "data": { "access_token": "...", "account_id": "..." }, "message": "..." }
    const payload = response.data;
    if (payload.status !== 'success' || !payload.data?.access_token) {
      throw new Error(payload.message || 'Health ID token exchange failed');
    }

    console.log('[HEALTH ID TOKEN] SUCCESS');
    return payload.data; // { access_token, token_type, expires_in, account_id }
  } catch (err) {
    if (err.response) {
      console.error('[HEALTH ID TOKEN] FAILED:', err.response.status, JSON.stringify(err.response.data));
    }
    throw err;
  }
}


/**
 * Step 3: Exchange Health ID access_token → Provider ID access_token
 * POST {Provider-URL}/api/v1/services/token
 * @param {string} healthIdToken - access_token from Health ID (Step 2)
 * @returns {object} Provider token data (access_token, account_id, username, etc.)
 */
async function exchangeToken(healthIdToken) {
  const response = await providerClient.post('/api/v1/services/token', {
    client_id:  config.providerApi.clientId,
    secret_key: config.providerApi.secretKey,
    token_by:   'Health ID',
    token:      healthIdToken,
  });

  if (response.data?.status !== 200) {
    throw new Error(response.data?.message || 'Provider token exchange failed');
  }
  return response.data.data;
}

/**
 * Step 4: Fetch Provider Profile
 * GET {Provider-URL}/api/v1/services/profile
 * @param {string} providerAccessToken
 * @returns {object} Full provider profile data
 */
async function fetchProfile(providerAccessToken) {
  const response = await providerClient.get('/api/v1/services/profile', {
    headers: {
      Authorization: `Bearer ${providerAccessToken}`,
      'client-id':   config.providerApi.clientId,
      'secret-key':  config.providerApi.secretKey,
    },
    params: {
      moph_idp_permission: '1',
      position_type:       '1',
    },
  });
  return response.data?.data || response.data;
}

module.exports = { exchangeHealthIdCode, exchangeToken, fetchProfile };
