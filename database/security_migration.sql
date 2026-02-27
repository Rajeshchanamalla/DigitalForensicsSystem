-- ============================================================
-- Security Migration Script
-- Blockchain-Based Digital Forensic System
-- Run this ONCE after the main schema.sql
-- ============================================================

USE forensic_system_db;

-- ─────────────────────────────────────────────────────────────
-- Table 1: ACCOUNT LOCKOUTS
-- Tracks failed login attempts and locked accounts
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS account_lockouts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL UNIQUE COMMENT 'User being tracked',
    failed_attempts INT NOT NULL DEFAULT 0 COMMENT 'Consecutive failed login count',
    locked_until DATETIME DEFAULT NULL COMMENT 'NULL = not locked; future datetime = locked until',
    last_attempt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Last failed attempt time',
    ip_address VARCHAR(45) DEFAULT NULL COMMENT 'IP of last failed attempt',
    INDEX idx_user_id (user_id),
    INDEX idx_locked_until (locked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracks failed login attempts and account lockouts';

-- ─────────────────────────────────────────────────────────────
-- Table 2: SECURITY ALERTS
-- Stores anomaly detections, brute-force events, lockouts, etc.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL COMMENT 'brute_force_detected | account_locked | multiple_ip_login | rate_limit_exceeded | ip_blocked',
    user_id VARCHAR(100) DEFAULT NULL COMMENT 'Affected user (NULL if IP-only event)',
    ip_address VARCHAR(45) DEFAULT NULL COMMENT 'Source IP address',
    description TEXT DEFAULT NULL COMMENT 'Human-readable alert description',
    severity VARCHAR(20) NOT NULL DEFAULT 'medium' COMMENT 'low | medium | high | critical',
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Admin has acknowledged this alert',
    resolved_by VARCHAR(100) DEFAULT NULL COMMENT 'Admin user ID who resolved this',
    resolved_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_alert_type (alert_type),
    INDEX idx_user_id (user_id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_severity (severity),
    INDEX idx_is_resolved (is_resolved),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Security events and anomaly alerts for admin review';

-- ─────────────────────────────────────────────────────────────
-- Table 3: IP BLOCKLIST
-- Admin-managed list of blocked IP addresses
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_blocklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE COMMENT 'IPv4 or IPv6 address to block',
    reason TEXT DEFAULT NULL COMMENT 'Reason for blocking (shown in 403 response)',
    blocked_by VARCHAR(100) DEFAULT NULL COMMENT 'Admin user ID who added this block',
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT NULL COMMENT 'NULL = permanent block; future datetime = auto-expires',
    INDEX idx_ip_address (ip_address),
    INDEX idx_expires_at (expires_at),
    INDEX idx_blocked_by (blocked_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Admin-managed IP address blocklist';

-- ─────────────────────────────────────────────────────────────
-- Verification Queries (uncomment and run to verify)
-- ─────────────────────────────────────────────────────────────
-- SHOW TABLES LIKE '%lockout%';
-- SHOW TABLES LIKE '%security%';
-- SHOW TABLES LIKE '%blocklist%';
-- DESCRIBE account_lockouts;
-- DESCRIBE security_alerts;
-- DESCRIBE ip_blocklist;
