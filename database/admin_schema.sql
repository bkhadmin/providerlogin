-- =============================================================
-- Admin System Schema Migration
-- Run this AFTER the main schema.sql
-- =============================================================

-- Admin accounts (separate from provider/OAuth users)
CREATE TABLE IF NOT EXISTS `admin_accounts` (
  `id`            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(50)      NOT NULL,
  `password_hash` VARCHAR(255)     NOT NULL,
  `display_name`  VARCHAR(100)     DEFAULT NULL,
  `role`          ENUM('superadmin','admin1','admin2','user') NOT NULL DEFAULT 'admin2',
  `is_active`     TINYINT(1)       NOT NULL DEFAULT 1,
  `last_login_at` DATETIME         DEFAULT NULL,
  `created_at`    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_admin_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Applications registry (replaces hardcoded list in apps.routes.js)
CREATE TABLE IF NOT EXISTS `applications` (
  `id`                 INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `app_id`             VARCHAR(50)   NOT NULL,
  `name`               VARCHAR(100)  NOT NULL,
  `description`        VARCHAR(255)  DEFAULT NULL,
  `icon`               VARCHAR(20)   NOT NULL DEFAULT '🔷',
  `url`                VARCHAR(500)  NOT NULL,
  `required_expertise` VARCHAR(100)  DEFAULT NULL COMMENT 'NULL = all users can access',
  `is_active`          TINYINT(1)    NOT NULL DEFAULT 1,
  `sort_order`         INT           NOT NULL DEFAULT 0,
  `created_at`         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_app_id` (`app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-user app access overrides
CREATE TABLE IF NOT EXISTS `user_app_access` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `app_id`     VARCHAR(50)     NOT NULL,
  `is_allowed` TINYINT(1)      NOT NULL DEFAULT 1,
  `granted_by` INT UNSIGNED    DEFAULT NULL COMMENT 'admin_accounts.id',
  `created_at` DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_user_app` (`user_id`, `app_id`),
  CONSTRAINT `fk_uaa_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- RBAC: menu definitions and minimum role required
CREATE TABLE IF NOT EXISTS `admin_menus` (
  `id`        INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `menu_key`  VARCHAR(50)  NOT NULL,
  `menu_label` VARCHAR(100) NOT NULL,
  `menu_icon` VARCHAR(10)  NOT NULL DEFAULT '📋',
  `min_role`  ENUM('superadmin','admin1','admin2','user') NOT NULL DEFAULT 'admin1',
  `sort_order` INT          NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_menu_key` (`menu_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================
-- Seed Data
-- =============================================================

INSERT IGNORE INTO `applications` (`app_id`, `name`, `description`, `icon`, `url`, `required_expertise`, `sort_order`) VALUES
('app-his',       'Hospital Information System', 'ระบบสารสนเทศโรงพยาบาล',       '🏥', 'https://his.example.com',                               NULL,            1),
('app-pharmacy',  'Pharmacy System',             'ระบบบริหารเวชภัณฑ์',            '💊', 'https://pharmacy.example.com',                          'เภสัชกรรม',     2),
('app-lab',       'Lab System',                  'ระบบห้องปฏิบัติการ',            '🔬', 'https://lab.example.com',                               NULL,            3),
('app-exceltrans','Excel Transfer',              'ระบบนำเข้า-ส่งออกข้อมูล Excel', '📊', 'http://localhost/bkexceltrans/sso_verify.php',           NULL,            4);

INSERT IGNORE INTO `admin_menus` (`menu_key`, `menu_label`, `menu_icon`, `min_role`, `sort_order`) VALUES
('apps_manage',   'จัดการ Application', '🗂️',  'admin2',     1),
('users_manage',  'จัดการ User',        '👥',  'admin1',     2),
('rbac_settings', 'ตั้งค่า RBAC',       '🔐',  'superadmin', 3);
