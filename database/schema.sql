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

  -- ชื่อ ภาษาไทย
  `title_th`          VARCHAR(50)  NULL COMMENT 'คำนำหน้า (ไทย)',
  `special_title_th`  VARCHAR(100) NULL COMMENT 'คำนำหน้าทางการแพทย์ (ไทย)',
  `firstname_th`      VARCHAR(100) NULL,
  `lastname_th`       VARCHAR(100) NULL,

  -- ชื่อ ภาษาอังกฤษ
  `title_en`          VARCHAR(50)  NULL COMMENT 'คำนำหน้า (EN)',
  `special_title_en`  VARCHAR(100) NULL,
  `firstname_en`      VARCHAR(100) NULL,
  `lastname_en`       VARCHAR(100) NULL,

  -- Timestamps
  `first_login_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login_at`     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_account_id` (`account_id`),
  KEY `idx_provider_id` (`provider_id`),
  KEY `idx_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='ข้อมูล Provider Profile จากระบบ Provider ID (สธ.)';


-- ─── ตาราง: สังกัดองค์กร ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `user_organizations` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`               BIGINT UNSIGNED NOT NULL,
  `hcode`                 VARCHAR(20)  NULL  COMMENT 'รหัสโรงพยาบาล',
  `hname_th`              VARCHAR(255) NULL  COMMENT 'ชื่อองค์กร (ไทย)',
  `hname_en`              VARCHAR(255) NULL  COMMENT 'ชื่อองค์กร (EN)',
  `position`              VARCHAR(255) NULL  COMMENT 'ตำแหน่ง',
  `expertise`             VARCHAR(255) NULL  COMMENT 'วิชาชีพเฉพาะ',
  `is_hr_admin`           TINYINT(1)   NOT NULL DEFAULT 0,
  `is_director`           TINYINT(1)   NOT NULL DEFAULT 0,
  `moph_access_token_idp` TEXT         NULL  COMMENT 'MOPH-JWT Token (IDP)',
  `synced_at`             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_hcode` (`hcode`),
  CONSTRAINT `fk_org_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='สังกัดองค์กรของ Provider (อาจมีมากกว่า 1)';


-- ─── ตาราง: ประวัติการ Login ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `login_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`     BIGINT UNSIGNED NULL    COMMENT 'NULL ถ้า login ไม่สำเร็จ',
  `account_id`  VARCHAR(50)     NULL,
  `username`    VARCHAR(100)    NULL,
  `ip_address`  VARCHAR(45)     NOT NULL COMMENT 'รองรับ IPv6',
  `user_agent`  TEXT            NULL,
  `event`       ENUM(
    'LOGIN_SUCCESS',
    'LOGIN_FAILURE',
    'LOGIN_NO_PROVIDER_ID',
    'LOGIN_UNAUTHORIZED',
    'LOGOUT',
    'SESSION_EXPIRED',
    'INVALID_STATE'
  ) NOT NULL,
  `error_msg`   VARCHAR(500)    NULL    COMMENT 'ข้อความ error (กรณีล้มเหลว)',
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_event` (`event`),
  KEY `idx_ip` (`ip_address`),
  KEY `idx_created_at` (`created_at`),
  CONSTRAINT `fk_log_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='ประวัติการ Login/Logout ทั้งหมด';


-- ─── View: สรุปการ Login ──────────────────────────────────────────────────────
CREATE OR REPLACE VIEW `v_login_summary` AS
SELECT
  u.account_id,
  u.username,
  CONCAT(u.firstname_th, ' ', u.lastname_th) AS fullname_th,
  u.provider_id,
  COUNT(l.id)           AS total_logins,
  SUM(l.event = 'LOGIN_SUCCESS')  AS success_count,
  SUM(l.event IN ('LOGIN_FAILURE','LOGIN_NO_PROVIDER_ID','LOGIN_UNAUTHORIZED')) AS failure_count,
  u.first_login_at,
  u.last_login_at
FROM `users` u
LEFT JOIN `login_logs` l ON l.user_id = u.id
GROUP BY u.id;
