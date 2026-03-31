'use strict';

require('dotenv').config();

const config = {
  // Server
  port: parseInt(process.env.PORT, 10) || 3000,
  env: process.env.NODE_ENV || 'development',
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  isProd: process.env.NODE_ENV === 'production',

  // Provider ID API
  providerApi: {
    baseUrl: process.env.PROVIDER_ID_BASE_URL || 'https://provider.id.th',
    clientId: process.env.PROVIDER_CLIENT_ID,
    secretKey: process.env.PROVIDER_SECRET_KEY,
  },

  // Health ID OAuth
  healthId: {
    oauthUrl:     (process.env.HEALTH_ID_OAUTH_URL     || 'https://moph.id.th').trim(),
    clientId:     (process.env.HEALTH_ID_CLIENT_ID     || '').trim(),
    clientSecret: (process.env.HEALTH_ID_CLIENT_SECRET || '').trim(),
    redirectUri:  (process.env.HEALTH_ID_REDIRECT_URI  || 'http://localhost:3000/callback').trim(),
    scopes: 'openid profile',
  },

  // Secrets
  jwt: {
    secret: process.env.JWT_SECRET || 'dev-secret-change-in-production',
    expiresIn: '8h',
    cookieName: 'pid_session',
  },
  sessionSecret: process.env.SESSION_SECRET || 'dev-session-secret-change-in-production',

  // CORS
  allowedOrigins: (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
    .split(',')
    .map(o => o.trim()),

  // Rate Limits
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,
    authMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 5,
  },

  // MySQL Database
  db: {
    host:            process.env.DB_HOST            || 'localhost',
    port:            parseInt(process.env.DB_PORT, 10) || 3306,
    user:            process.env.DB_USER            || 'root',
    password:        process.env.DB_PASSWORD        || '',
    name:            process.env.DB_NAME            || 'providerlogin',
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT, 10) || 10,
  },
};

// Validate critical config in production
if (config.isProd) {
  const requiredKeys = [
    ['providerApi.clientId', config.providerApi.clientId],
    ['providerApi.secretKey', config.providerApi.secretKey],
    ['healthId.clientId', config.healthId.clientId],
    ['healthId.clientSecret', config.healthId.clientSecret],
    ['jwt.secret', config.jwt.secret],
    ['db.password', config.db.password],
  ];
  for (const [key, value] of requiredKeys) {
    if (!value || value.startsWith('dev-') || value.includes('change')) {
      throw new Error(`[Config] Missing or insecure value for: ${key}`);
    }
  }
}

module.exports = config;
