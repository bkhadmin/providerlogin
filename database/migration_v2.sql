-- =============================================================
-- Migration v2 — Audit, App Usage, IP Allowlist, hcode filter
-- Run AFTER schema.sql + admin_schema.sql
-- =============================================================

USE `providerlogin`;

-- ─── 1. Admin Action Audit Log ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_audit_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `admin_id`    INT UNSIGNED    NULL     COMMENT 'admin_accounts.id',
  `username`    VARCHAR(50)     NULL,
  `role`        VARCHAR(20)     NULL,
  `action`      VARCHAR(100)    NOT NULL COMMENT 'เช่น CREATE_APP, UPDATE_USER_ACCESS',
  `target_type` VARCHAR(50)     NULL     COMMENT 'เช่น app, user, admin, ip',
  `target_id`   VARCHAR(100)    NULL     COMMENT 'id หรือ app_id ของ target',
  `detail`      TEXT            NULL     COMMENT 'JSON รายละเอียดเพิ่มเติม',
  `ip_address`  VARCHAR(45)     NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_admin_id`   (`admin_id`),
  KEY `idx_action`     (`action`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='บันทึกการกระทำของ Admin ทุกครั้ง';

-- ─── 2. App Access Log (SSO token issued) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS `app_access_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`     BIGINT UNSIGNED NULL,
  `account_id`  VARCHAR(50)     NULL,
  `username`    VARCHAR(100)    NULL,
  `app_id`      VARCHAR(50)     NOT NULL,
  `app_name`    VARCHAR(100)    NULL,
  `ip_address`  VARCHAR(45)     NULL,
  `user_agent`  TEXT            NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id`    (`user_id`),
  KEY `idx_app_id`     (`app_id`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='บันทึกการเปิดใช้งาน App ผ่าน SSO token';

-- ─── 3. Admin IP Allowlist ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_ip_allowlist` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip`         VARCHAR(45)  NOT NULL COMMENT 'IPv4 หรือ IPv6 หรือ CIDR เช่น 192.168.1.0/24',
  `label`      VARCHAR(100) NULL     COMMENT 'คำอธิบาย เช่น "สำนักงาน", "VPN"',
  `is_active`  TINYINT(1)   NOT NULL DEFAULT 1,
  `added_by`   INT UNSIGNED NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='IP ที่อนุญาตให้เข้าถึง Admin Panel (ถ้าตารางว่าง = ไม่จำกัด IP)';

-- ─── 4. hcode_whitelist column บน applications ──────────────────────────────
ALTER TABLE `applications`
  ADD COLUMN IF NOT EXISTS `hcode_whitelist` VARCHAR(1000) NULL
  COMMENT 'JSON array ของ hcode ที่เข้าถึงได้ เช่น ["10669","10701"] — NULL = ทุก hcode'
  AFTER `required_expertise`;

-- ─── 5. totp_secret column บน admin_accounts (ถ้ายังไม่มี) ─────────────────
ALTER TABLE `admin_accounts`
  ADD COLUMN IF NOT EXISTS `totp_secret` VARCHAR(100) NULL
  AFTER `is_active`;

-- ─── 6. เพิ่ม menu สำหรับ features ใหม่ ───────────────────────────────────
INSERT IGNORE INTO `admin_menus` (`menu_key`, `menu_label`, `menu_icon`, `min_role`, `sort_order`) VALUES
('dashboard',    'Dashboard',           '📊', 'admin2',     0),
('logs_login',   'Login Logs',          '📋', 'admin1',     4),
('logs_app',     'App Usage',           '🔗', 'admin1',     5),
('logs_audit',   'Admin Audit',         '🛡️', 'superadmin', 6),
('ip_allowlist', 'IP Allowlist',        '🔒', 'superadmin', 7);
