'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const path = require('path');

const config = require('./config/config');
const {
  helmetMiddleware,
  corsMiddleware,
  globalLimiter,
  hppMiddleware,
  setCsrfToken,
} = require('./middleware/security');
const { auditMiddleware, logger } = require('./middleware/audit');
const { testConnection } = require('./database/db');
const authRoutes  = require('./routes/auth.routes');
const appsRoutes  = require('./routes/apps.routes');
const adminRoutes = require('./routes/admin.routes');
const { ipAllowlistMiddleware } = require('./middleware/ipAllowlist');

const app = express();

// ─── Trust proxy (needed behind Nginx/load balancer) ─────────────────────────
app.set('trust proxy', 1);

// ─── Security Middleware (order matters) ──────────────────────────────────────
app.use(helmetMiddleware);
app.use(corsMiddleware);
app.use(hppMiddleware);
app.use(globalLimiter);

// ─── Request Parsing ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));        // Limit body size
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// ─── Logging ──────────────────────────────────────────────────────────────────
app.use(morgan('combined', {
  stream: { write: (msg) => logger.info({ event: 'HTTP', message: msg.trim() }) },
}));
app.use(auditMiddleware);

// ─── CSRF Token (set on all responses before routes) ─────────────────────────
app.use(setCsrfToken);

// ─── Static Frontend ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,           // We handle root manually
  maxAge: '1h',
}));

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',  authRoutes);
app.use('/api/apps',  appsRoutes);
app.use('/api/admin', ipAllowlistMiddleware, adminRoutes);

// ─── Frontend Routes ──────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// OAuth callback: Health ID redirects here → serve callback.html
// callback.html จะ POST code+state ไปที่ /api/auth/callback เอง
app.get('/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'callback.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ success: false, message: 'API endpoint not found.' });
  }
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error({ event: 'UNHANDLED_ERROR', message: err.message, stack: err.stack });

  // Don't leak stack traces to client
  const status = err.status || err.statusCode || 500;
  const message = config.isProd ? 'Internal server error.' : err.message;
  res.status(status).json({ success: false, message });
});

// ─── Start Server (after DB is ready) ────────────────────────────────────────
(async () => {
  await testConnection(); // ตรวจสอบ MySQL ก่อน start รับ request

  const server = app.listen(config.port, () => {
    logger.info({
      event: 'SERVER_STARTED',
      port: config.port,
      env: config.env,
      url: config.baseUrl,
    });
    console.log(`\n🚀 Provider Login Server running at ${config.baseUrl}`);
    console.log(`📋 Environment: ${config.env}`);
    console.log(`🔒 Security: Helmet + Rate Limit + CSRF + CORS enabled`);
    console.log(`🗄️  Database: MySQL connected (${config.db.host}/${config.db.name})\n`);
  });

  // ─── Graceful Shutdown ──────────────────────────────────────────────────────
  function gracefulShutdown(signal) {
    logger.info({ event: 'SHUTDOWN', signal });
    server.close(() => {
      console.log('\n✅ Server closed gracefully.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 5000);
  }

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
})();
process.on('uncaughtException', (err) => {
  logger.error({ event: 'UNCAUGHT_EXCEPTION', message: err.message, stack: err.stack });
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logger.error({ event: 'UNHANDLED_REJECTION', reason: String(reason) });
});

module.exports = app;
