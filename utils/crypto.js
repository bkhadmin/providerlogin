'use strict';

const crypto = require('crypto');

/**
 * Generate a cryptographically secure random state nonce (for CSRF in OAuth)
 * @returns {string} hex string
 */
function generateState() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate PKCE code_verifier (RFC 7636)
 * @returns {string} base64url encoded random string
 */
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Derive PKCE code_challenge from code_verifier
 * @param {string} verifier
 * @returns {string} base64url encoded SHA-256 hash
 */
function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

module.exports = { generateState, generateCodeVerifier, generateCodeChallenge };
