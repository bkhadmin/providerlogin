'use strict';
/**
 * app.js - Secure frontend utility
 * 
 * SECURITY RULES:
 * - NEVER store tokens in localStorage or sessionStorage (XSS vulnerable)
 * - Tokens are stored in httpOnly cookies managed by the server
 * - Always send X-CSRF-Token header on non-GET requests
 * - All API calls use credentials: 'include' for cookie transport
 */

/**
 * Read a cookie value by name
 * @param {string} name
 * @returns {string}
 */
function getCookie(name) {
  const match = document.cookie.split(';')
    .map(c => c.trim())
    .find(c => c.startsWith(name + '='));
  return match ? decodeURIComponent(match.split('=')[1]) : '';
}

/**
 * Secure fetch wrapper that automatically adds CSRF token for mutating requests
 * @param {string} url
 * @param {RequestInit} options
 * @returns {Promise<Response>}
 */
async function secureFetch(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers['X-CSRF-Token'] = getCookie('csrf_token');
  }

  return fetch(url, {
    ...options,
    headers,
    credentials: 'include', // Always send cookies
  });
}

/**
 * Check authentication status
 * @returns {Promise<{authenticated: boolean, username?: string}>}
 */
async function checkAuthStatus() {
  try {
    const res = await secureFetch('/api/auth/status');
    return await res.json();
  } catch {
    return { authenticated: false };
  }
}

// Make helpers globally available
window.secureFetch = secureFetch;
window.getCookie = getCookie;
window.checkAuthStatus = checkAuthStatus;
