'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config/config');

/**
 * Sign a JWT token from provider profile data
 * @param {object} payload - Data to encode in token
 * @returns {string} Signed JWT
 */
function signToken(payload) {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
    issuer: 'providerlogin',
    audience: 'web-apps',
  });
}

/**
 * Verify a JWT token
 * @param {string} token
 * @returns {object} Decoded payload
 */
function verifyToken(token) {
  return jwt.verify(token, config.jwt.secret, {
    issuer: 'providerlogin',
    audience: 'web-apps',
  });
}

module.exports = { signToken, verifyToken };
