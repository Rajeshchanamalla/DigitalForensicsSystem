-- MySQL Database Schema for Digital Forensic Evidence Management System
-- Login Logs Table

CREATE DATABASE IF NOT EXISTS forensic_system_db;
USE forensic_system_db;

-- Login Logs Table
CREATE TABLE IF NOT EXISTS login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) DEFAULT NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_role (role),
    INDEX idx_success (success),
    INDEX idx_timestamp (timestamp),
    INDEX idx_user_timestamp (user_id, timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sample query to view all logs
-- SELECT * FROM login_logs ORDER BY timestamp DESC;

-- Users Table (for storing all users with hashed passwords)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_user_id (user_id),
    INDEX idx_role (role),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default users (passwords will be hashed by application)
-- Note: These are placeholders. Actual passwords should be hashed using bcrypt
-- Default password for all: same as user_id + "123" (e.g., investigator1 -> "invest123")
-- You can insert these after running the application, or insert them manually with hashed passwords

-- Sample query to view all users
-- SELECT user_id, role, is_default, created_at FROM users WHERE is_active = 1;

-- Sample query to get statistics
-- SELECT 
--     COUNT(*) as total,
--     SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
--     SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
--     COUNT(DISTINCT user_id) as unique_users
-- FROM login_logs;

