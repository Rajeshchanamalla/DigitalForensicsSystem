/**
 * Security Utilities
 * Provides: rate limiting, account lockout, input sanitization,
 * IP blocklist enforcement, and anomaly detection.
 */

const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const config = require('../config');

// Shared DB pool for security checks
const pool = mysql.createPool(config.database);

// ─────────────────────────────────────────────
// 1. RATE LIMITERS
// ─────────────────────────────────────────────

/**
 * Global rate limiter — applies to all API routes.
 * Allows 100 requests per 15-minute window per IP.
 */
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 100,
    standardHeaders: true,       // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false,
    message: {
        error: 'Too many requests from this IP, please try again after 15 minutes.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    handler: async (req, res, next, options) => {
        // Log as a security alert
        try {
            await pool.execute(
                `INSERT INTO security_alerts (alert_type, user_id, ip_address, description, severity)
                 VALUES ('rate_limit_exceeded', NULL, ?, 'Global rate limit exceeded', 'medium')`,
                [req.ip || 'N/A']
            );
        } catch (e) { /* non-fatal — table may not exist yet */ }
        res.status(429).json(options.message);
    }
});

/**
 * Strict login rate limiter — applies only to POST /api/users/verify.
 * Allows 5 attempts per 15-minute window per IP.
 */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // Only count failed/errored requests
    message: {
        error: 'Too many login attempts from this IP. Please try again after 15 minutes.',
        code: 'LOGIN_RATE_LIMIT_EXCEEDED'
    },
    handler: async (req, res, next, options) => {
        try {
            await pool.execute(
                `INSERT INTO security_alerts (alert_type, user_id, ip_address, description, severity)
                 VALUES ('brute_force_detected', ?, ?, 'Login rate limit exceeded — possible brute-force attack', 'high')`,
                [req.body?.userId || 'unknown', req.ip || 'N/A']
            );
        } catch (e) { /* non-fatal */ }
        res.status(429).json(options.message);
    }
});

// ─────────────────────────────────────────────
// 2. ACCOUNT LOCKOUT
// ─────────────────────────────────────────────

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

/**
 * Middleware: Check if a user account is locked before processing login.
 * Must be used before any password-check logic.
 */
async function accountLockoutCheck(req, res, next) {
    const { userId } = req.body;
    if (!userId) return next();

    try {
        const [rows] = await pool.execute(
            'SELECT failed_attempts, locked_until FROM account_lockouts WHERE user_id = ?',
            [userId]
        );

        if (rows.length > 0) {
            const record = rows[0];
            if (record.locked_until && new Date(record.locked_until) > new Date()) {
                const remaining = Math.ceil((new Date(record.locked_until) - new Date()) / 60000);
                return res.status(403).json({
                    error: `Account is temporarily locked due to too many failed login attempts. Try again in ${remaining} minute(s).`,
                    code: 'ACCOUNT_LOCKED',
                    lockedUntil: record.locked_until
                });
            }
        }
        next();
    } catch (error) {
        // If table doesn't exist yet, skip lockout check
        if (error.code === 'ER_NO_SUCH_TABLE') return next();
        console.error('Lockout check error:', error.message);
        next();
    }
}

/**
 * Record a failed login attempt. Locks account after MAX_FAILED_ATTEMPTS.
 */
async function recordFailedAttempt(userId, ipAddress) {
    try {
        const [existing] = await pool.execute(
            'SELECT id, failed_attempts FROM account_lockouts WHERE user_id = ?',
            [userId]
        );

        if (existing.length === 0) {
            await pool.execute(
                `INSERT INTO account_lockouts (user_id, failed_attempts, last_attempt, ip_address)
                 VALUES (?, 1, NOW(), ?)`,
                [userId, ipAddress || 'N/A']
            );
        } else {
            const newCount = existing[0].failed_attempts + 1;
            let lockedUntil = null;

            if (newCount >= MAX_FAILED_ATTEMPTS) {
                lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);

                // Log a high-severity alert
                await pool.execute(
                    `INSERT INTO security_alerts (alert_type, user_id, ip_address, description, severity)
                     VALUES ('account_locked', ?, ?, ?, 'critical')`,
                    [userId, ipAddress || 'N/A',
                        `Account '${userId}' locked after ${newCount} failed login attempts from IP ${ipAddress}`]
                );
            }

            await pool.execute(
                `UPDATE account_lockouts
                 SET failed_attempts = ?, locked_until = ?, last_attempt = NOW(), ip_address = ?
                 WHERE user_id = ?`,
                [newCount, lockedUntil, ipAddress || 'N/A', userId]
            );
        }
    } catch (error) {
        if (error.code !== 'ER_NO_SUCH_TABLE') {
            console.error('Error recording failed attempt:', error.message);
        }
    }
}

/**
 * Clear lockout record after a successful login.
 */
async function clearLockout(userId) {
    try {
        await pool.execute(
            'DELETE FROM account_lockouts WHERE user_id = ?',
            [userId]
        );
    } catch (error) {
        if (error.code !== 'ER_NO_SUCH_TABLE') {
            console.error('Error clearing lockout:', error.message);
        }
    }
}

// ─────────────────────────────────────────────
// 3. INPUT SANITIZATION
// ─────────────────────────────────────────────

/**
 * Middleware: Strip dangerous HTML/script content from all string fields in req.body.
 * Prevents XSS via stored content and log injection.
 */
function sanitizeInputs(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        req.body = deepSanitize(req.body);
    }
    next();
}

function deepSanitize(obj) {
    if (typeof obj === 'string') {
        return obj
            .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')   // Remove script blocks
            .replace(/<[^>]+>/g, '')                                  // Strip all HTML tags
            .replace(/\x00/g, '')                                     // Remove null bytes
            .replace(/javascript:/gi, '')                             // Remove JS protocol
            .replace(/on\w+\s*=/gi, '')                              // Remove event handlers (onclick= etc.)
            .trim();
    }
    if (Array.isArray(obj)) {
        return obj.map(deepSanitize);
    }
    if (obj !== null && typeof obj === 'object') {
        const sanitized = {};
        for (const key of Object.keys(obj)) {
            sanitized[key] = deepSanitize(obj[key]);
        }
        return sanitized;
    }
    return obj;
}

// ─────────────────────────────────────────────
// 4. IP BLOCKLIST
// ─────────────────────────────────────────────

/**
 * Middleware: Block requests from IPs listed in the ip_blocklist table.
 * Skips if the table doesn't exist yet.
 */
async function checkIpBlocklist(req, res, next) {
    const ip = req.ip || req.connection?.remoteAddress || 'N/A';

    // Always allow localhost
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        return next();
    }

    try {
        const [rows] = await pool.execute(
            `SELECT id, reason, expires_at FROM ip_blocklist
             WHERE ip_address = ?
             AND (expires_at IS NULL OR expires_at > NOW())`,
            [ip]
        );

        if (rows.length > 0) {
            return res.status(403).json({
                error: 'Access denied. Your IP address has been blocked.',
                code: 'IP_BLOCKED',
                reason: rows[0].reason || 'Suspicious activity'
            });
        }
        next();
    } catch (error) {
        if (error.code === 'ER_NO_SUCH_TABLE') return next();
        console.error('IP blocklist check error:', error.message);
        next(); // Fail open — do not block legitimate users on DB errors
    }
}

// ─────────────────────────────────────────────
// 5. ANOMALY / SUSPICIOUS ACTIVITY DETECTOR
// ─────────────────────────────────────────────

/**
 * After a successful login, check if the same user is logging in from
 * multiple distinct IPs within the last 1 hour. If so, flag it.
 */
async function detectSuspiciousActivity(userId, ipAddress) {
    try {
        // Get unique IPs this user logged in from in the last hour
        const [recentIPs] = await pool.execute(
            `SELECT DISTINCT ip_address
             FROM login_logs
             WHERE user_id = ? AND success = 1
             AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
            [userId]
        );

        const uniqueIPs = recentIPs.map(r => r.ip_address).filter(ip => ip && ip !== 'N/A');
        const currentIPNew = !uniqueIPs.includes(ipAddress);

        if (uniqueIPs.length >= 2 && currentIPNew) {
            await pool.execute(
                `INSERT INTO security_alerts
                 (alert_type, user_id, ip_address, description, severity)
                 VALUES ('multiple_ip_login', ?, ?, ?, 'high')`,
                [
                    userId,
                    ipAddress || 'N/A',
                    `User '${userId}' logged in from ${uniqueIPs.length + 1} different IPs within 1 hour. ` +
                    `IPs: ${[...uniqueIPs, ipAddress].join(', ')}`
                ]
            );
            console.warn(`[SECURITY ALERT] Multiple IP login detected for user: ${userId}`);
        }
    } catch (error) {
        if (error.code !== 'ER_NO_SUCH_TABLE') {
            console.error('Anomaly detection error:', error.message);
        }
    }
}

module.exports = {
    globalLimiter,
    loginLimiter,
    accountLockoutCheck,
    recordFailedAttempt,
    clearLockout,
    sanitizeInputs,
    checkIpBlocklist,
    detectSuspiciousActivity
};
