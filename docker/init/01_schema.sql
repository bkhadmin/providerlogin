-- =====================================================
-- Provider Login System - MySQL Database Schema
-- =====================================================

CREATE DATABASE IF NOT EXISTS `providerlogin`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `providerlogin`;

-- ─── ตาราง: ผู้ใช้งาน (Provider Profile) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS `users` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `account_id`        VARCHAR(50)  NOT NULL COMMENT 'Provider ID account_id',
  `provider_id`       VARCHAR(50)  NULL COMMENT 'เลข Provider ID',
  `hash_cid`          VARCHAR(100) NULL COMMENT 'Hash CID',
  `username`          VARCHAR(100) NOT NULL,
  `title_th`          VARCHAR(50)  NULL,
  `special_title_th`  VARCHAR(100) NULL,
  `firstname_th`      VARCHAR(100) NULL,
  `lastname_th`       VARCHAR(100) NULL,
  `title_en`          VARCHAR(50)  NULL,
  `special_title_en`  VARCHAR(100) NULL,
  `firstname_en`      VARCHAR(100) NULL,
  `lastname_en`       VARCHAR(100) NULL,
  `first_login_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login_at`     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_account_id` (`account_id`),
  KEY `idx_provider_id` (`provider_id`),
  KEY `idx_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── ตาราง: สังกัดองค์กร ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `user_organizations` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`               BIGINT UNSIGNED NOT NULL,
  `hcode`                 VARCHAR(20)  NULL,
  `hname_th`              VARCHAR(255) NULL,
  `hname_en`              VARCHAR(255) NULL,
  `position`              VARCHAR(255) NULL,
  `expertise`             VARCHAR(255) NULL,
  `is_hr_admin`           TINYINT(1)   NOT NULL DEFAULT 0,
  `is_director`           TINYINT(1)   NOT NULL DEFAULT 0,
  `moph_access_token_idp` TEXT         NULL,
  `synced_at`             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_hcode` (`hcode`),
  CONSTRAINT `fk_org_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── ตาราง: ประวัติการ Login ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `login_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`     BIGINT UNSIGNED NULL,
  `account_id`  VARCHAR(50)     NULL,
  `username`    VARCHAR(100)    NULL,
  `ip_address`  VARCHAR(45)     NOT NULL,
  `user_agent`  TEXT            NULL,
  `event`       ENUM('LOGIN_SUCCESS','LOGIN_FAILURE','LOGIN_NO_PROVIDER_ID','LOGIN_UNAUTHORIZED','LOGOUT','SESSION_EXPIRED','INVALID_STATE') NOT NULL,
  `error_msg`   VARCHAR(500)    NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_event` (`event`),
  KEY `idx_created_at` (`created_at`),
  CONSTRAINT `fk_log_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── View: สรุปการ Login ──────────────────────────────────────────────────────
CREATE OR REPLACE VIEW `v_login_summary` AS
SELECT
  u.account_id, u.username,
  CONCAT(u.firstname_th, ' ', u.lastname_th) AS fullname_th,
  u.provider_id,
  COUNT(l.id) AS total_logins,
  SUM(l.event = 'LOGIN_SUCCESS') AS success_count,
  SUM(l.event IN ('LOGIN_FAILURE','LOGIN_NO_PROVIDER_ID','LOGIN_UNAUTHORIZED')) AS failure_count,
  u.first_login_at, u.last_login_at
FROM `users` u
LEFT JOIN `login_logs` l ON l.user_id = u.id
GROUP BY u.id;

-- ─── Admin Accounts ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_accounts` (
  `id`            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(50)      NOT NULL,
  `password_hash` VARCHAR(255)     NOT NULL,
  `display_name`  VARCHAR(100)     DEFAULT NULL,
  `role`          ENUM('superadmin','admin1','admin2','user') NOT NULL DEFAULT 'admin2',
  `is_active`     TINYINT(1)       NOT NULL DEFAULT 1,
  `totp_secret`   VARCHAR(100)     NULL,
  `last_login_at` DATETIME         DEFAULT NULL,
  `created_at`    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_admin_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Applications ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `applications` (
  `id`                 INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `app_id`             VARCHAR(50)   NOT NULL,
  `name`               VARCHAR(100)  NOT NULL,
  `description`        VARCHAR(255)  DEFAULT NULL,
  `icon`               VARCHAR(20)   NOT NULL DEFAULT '🔷',
  `url`                VARCHAR(500)  NOT NULL,
  `required_expertise` VARCHAR(100)  DEFAULT NULL,
  `hcode_whitelist`    VARCHAR(1000) NULL,
  `is_active`          TINYINT(1)    NOT NULL DEFAULT 1,
  `sort_order`         INT           NOT NULL DEFAULT 0,
  `created_at`         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_app_id` (`app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── User App Access ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `user_app_access` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `app_id`     VARCHAR(50)     NOT NULL,
  `is_allowed` TINYINT(1)      NOT NULL DEFAULT 1,
  `granted_by` INT UNSIGNED    DEFAULT NULL,
  `created_at` DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_user_app` (`user_id`, `app_id`),
  CONSTRAINT `fk_uaa_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Position App Access ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `position_app_access` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `position`   VARCHAR(255)    NOT NULL,
  `app_id`     VARCHAR(50)     NOT NULL,
  `is_allowed` TINYINT(1)      NOT NULL DEFAULT 1,
  `granted_by` INT UNSIGNED    DEFAULT NULL,
  `created_at` DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_pos_app` (`position`, `app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Admin Menus ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_menus` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `menu_key`   VARCHAR(50)  NOT NULL,
  `menu_label` VARCHAR(100) NOT NULL,
  `menu_icon`  VARCHAR(10)  NOT NULL DEFAULT '📋',
  `min_role`   ENUM('superadmin','admin1','admin2','user') NOT NULL DEFAULT 'admin1',
  `sort_order` INT          NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_menu_key` (`menu_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Admin Audit Logs ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_audit_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `admin_id`    INT UNSIGNED    NULL,
  `username`    VARCHAR(50)     NULL,
  `role`        VARCHAR(20)     NULL,
  `action`      VARCHAR(100)    NOT NULL,
  `target_type` VARCHAR(50)     NULL,
  `target_id`   VARCHAR(100)    NULL,
  `detail`      TEXT            NULL,
  `ip_address`  VARCHAR(45)     NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_action` (`action`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── App Access Logs ──────────────────────────────────────────────────────────
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
  KEY `idx_app_id` (`app_id`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Admin IP Allowlist ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_ip_allowlist` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip`         VARCHAR(45)  NOT NULL,
  `label`      VARCHAR(100) NULL,
  `is_active`  TINYINT(1)   NOT NULL DEFAULT 1,
  `added_by`   INT UNSIGNED NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Seed: Admin Menus ────────────────────────────────────────────────────────
INSERT IGNORE INTO `admin_menus` (`menu_key`, `menu_label`, `menu_icon`, `min_role`, `sort_order`) VALUES
('dashboard',    'Dashboard',          '📊', 'admin2',     0),
('apps_manage',  'จัดการ Application', '🗂️', 'admin2',     1),
('users_manage', 'จัดการ User',        '👥', 'admin1',     2),
('rbac_settings','ตั้งค่า RBAC',       '🔐', 'superadmin', 3),
('logs_login',   'Login Logs',         '📋', 'admin1',     4),
('logs_app',     'App Usage',          '🔗', 'admin1',     5),
('logs_audit',   'Admin Audit',        '🛡️', 'superadmin', 6),
('ip_allowlist', 'IP Allowlist',       '🔒', 'superadmin', 7),
('2fa_settings', 'ตั้งค่า 2FA',        '🔑', 'superadmin', 8);
