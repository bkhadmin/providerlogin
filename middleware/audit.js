'use strict';

const winston = require('winston');
const path = require('path');
const fs = require('fs');

const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: path.join(logsDir, 'audit.log') }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize({ level: true }),
        winston.format.printf(({ level, message, event, error, timestamp, ...rest }) => {
          const parts = [level];
          if (event)   parts.push(`[${event}]`);
          if (message) parts.push(message);
          if (error)   parts.push(`→ ${error}`);
          // show any remaining fields compactly
          const extra = Object.keys(rest).filter(k => k !== 'timestamp' && rest[k] !== undefined);
          if (extra.length) parts.push(JSON.stringify(Object.fromEntries(extra.map(k => [k, rest[k]]))));
          return parts.join(' ');
        })
      ),
    }),
  ],
});

/**
 * Log an authentication event with metadata
 * @param {string} event - Event name e.g. 'LOGIN_SUCCESS', 'LOGIN_FAILURE'
 * @param {object} req - Express request object
 * @param {object} [extra] - Additional fields to log
 */
function auditLog(event, req, extra = {}) {
  logger.info({
    event,
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.headers['user-agent'],
    method: req.method,
    path: req.path,
    timestamp: new Date().toISOString(),
    ...extra,
  });
}

/**
 * Audit middleware - logs every request at info level
 */
function auditMiddleware(req, res, next) {
  res.on('finish', () => {
    if (req.path.startsWith('/api/auth')) {
      auditLog('API_REQUEST', req, { status: res.statusCode });
    }
  });
  next();
}

module.exports = { auditLog, auditMiddleware, logger };
