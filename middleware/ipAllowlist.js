'use strict';

const { getActiveIpAllowlist } = require('../database/adminModel');

// cache IP list เพื่อไม่ query DB ทุก request (refresh ทุก 60 วินาที)
let _cache = null;
let _cacheAt = 0;
const CACHE_TTL = 60 * 1000;

async function getList() {
  const now = Date.now();
  if (_cache && now - _cacheAt < CACHE_TTL) return _cache;
  _cache  = await getActiveIpAllowlist();
  _cacheAt = now;
  return _cache;
}

/** ล้าง cache ทันที (เรียกหลัง add/remove IP) */
function invalidateCache() {
  _cache  = null;
  _cacheAt = 0;
}

/**
 * ตรวจสอบว่า IP ตรงกับ entry ใน allowlist ไหม
 * รองรับ exact match และ CIDR (IPv4 เท่านั้น)
 */
function ipInRange(clientIp, entry) {
  if (!entry.includes('/')) return clientIp === entry;
  // CIDR check (IPv4 only)
  try {
    const [range, bits] = entry.split('/');
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1) >>> 0;
    const toInt = ip => ip.split('.').reduce((acc, b) => (acc << 8) | parseInt(b, 10), 0) >>> 0;
    return (toInt(clientIp) & mask) === (toInt(range) & mask);
  } catch {
    return false;
  }
}

/**
 * Middleware: ถ้า allowlist ว่าง = ไม่จำกัด IP
 * ถ้ามี entry ใดๆ = เฉพาะ IP ในรายการ (active) เท่านั้น
 */
async function ipAllowlistMiddleware(req, res, next) {
  try {
    const list = await getList();
    if (!list.length) return next(); // allowlist ว่าง = ไม่จำกัด

    const clientIp = (req.ip || '').replace(/^::ffff:/, '');
    const allowed  = list.some(entry => ipInRange(clientIp, entry));

    if (!allowed) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: IP not in allowlist.',
      });
    }
    next();
  } catch {
    // ถ้า DB error ให้ผ่านไปก่อน (fail-open) เพื่อไม่ให้ระบบล็อกตัวเอง
    next();
  }
}

module.exports = { ipAllowlistMiddleware, invalidateCache };
