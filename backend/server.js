/**
 * Express Backend Server with MySQL Integration
 * API Server for Digital Forensic System
 */

const express = require('express');
const helmet = require('helmet');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const config = require('./config');
const { generateToken, authenticate, authorize } = require('./middleware/auth');
const { generateEncryptionKey, hashEncryptionKey } = require('./utils/encryption');
const { notifyEvidenceUploaded, notifyEvidenceVerified, notifyStatusChange } = require('./utils/email');
const { generateEvidenceReport, generateCaseReport } = require('./utils/pdf');
const { storeEvidenceOnBlockchain, verifyEvidenceOnBlockchain, addVerificationToBlockchain, printBlockchainHistory, initializeBlockchain } = require('./utils/blockchain');
const {
    globalLimiter,
    loginLimiter,
    accountLockoutCheck,
    recordFailedAttempt,
    clearLockout,
    sanitizeInputs,
    checkIpBlocklist,
    detectSuspiciousActivity
} = require('./utils/security');
const path = require('path');
const fs = require('fs');

// Initialize Blockchain History on startup
setTimeout(async () => {
    await initializeBlockchain();
    printBlockchainHistory().catch(err => console.error('Error printing blockchain history:', err.message));
}, 3000); // Wait for connection

const app = express();
const PORT = config.server.port;

// ── Security Middleware (applied globally, before all routes) ──
app.use(helmet({                              // HTTP security headers
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // Allow IPFS gateway images
    contentSecurityPolicy: false              // Disable CSP (frontend uses inline scripts — safe in local dev)
}));
app.use(globalLimiter);                       // Rate limit: 100 req/15min per IP
app.use(checkIpBlocklist);                    // Block requests from admin-blocked IPs
app.use(sanitizeInputs);                      // Strip XSS payloads from all request bodies

// ── Standard Middleware ──
app.use(cors(config.server.cors));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create MySQL connection pool
const pool = mysql.createPool(config.database);

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('✅ MySQL Database connected successfully!');
        connection.release();
    })
    .catch(error => {
        console.error('❌ MySQL Database connection failed:', error.message);
        console.error('   Please check your MySQL configuration in backend/config.js');
        console.error('   Make sure MySQL is running and database exists.');
    });

// ==================== API ROUTES ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        message: 'API Server is running',
        database: 'Connected'
    });
});

// Get Blockchain Config (Contract Address)
app.get('/api/config/contract', (req, res) => {
    try {
        const dataPath = path.resolve(__dirname, '../blockchain-data.json');
        if (fs.existsSync(dataPath)) {
            const contractData = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
            res.json({
                success: true,
                address: contractData.address,
                network: contractData.network
            });
        } else {
            res.status(404).json({ error: 'Blockchain data not found' });
        }
    } catch (error) {
        console.error('Error fetching contract config:', error);
        res.status(500).json({ error: 'Failed to fetch contract config' });
    }
});

// Insert login log
app.post('/api/login-logs', async (req, res) => {
    try {
        const { userId, role, success, ipAddress } = req.body;

        // Validation
        if (!userId || !role || success === undefined) {
            return res.status(400).json({
                error: 'Missing required fields: userId, role, success'
            });
        }

        // Get client IP address if not provided
        const clientIp = ipAddress || req.ip || req.connection.remoteAddress || 'N/A';

        // Insert into database
        const [result] = await pool.execute(
            `INSERT INTO login_logs (user_id, role, success, ip_address) 
             VALUES (?, ?, ?, ?)`,
            [userId, role, success ? 1 : 0, clientIp]
        );

        res.json({
            success: true,
            message: 'Login log inserted successfully',
            id: result.insertId
        });
    } catch (error) {
        console.error('Error inserting login log:', error);
        res.status(500).json({
            error: 'Failed to insert login log',
            message: error.message
        });
    }
});

// Get all login logs
app.get('/api/login-logs', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT 
                id,
                user_id as userId,
                role,
                success,
                timestamp,
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') as timestampReadable,
                ip_address as ipAddress
             FROM login_logs 
             ORDER BY timestamp DESC`
        );

        // Convert success (0/1) to boolean
        const logs = rows.map(row => ({
            ...row,
            success: Boolean(row.success)
        }));

        res.json({
            success: true,
            count: logs.length,
            logs: logs
        });
    } catch (error) {
        console.error('Error fetching login logs:', error);
        res.status(500).json({
            error: 'Failed to fetch login logs',
            message: error.message
        });
    }
});

// Get logs by user ID
app.get('/api/login-logs/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const [rows] = await pool.execute(
            `SELECT 
                id,
                user_id as userId,
                role,
                success,
                timestamp,
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') as timestampReadable,
                ip_address as ipAddress
             FROM login_logs 
             WHERE user_id = ?
             ORDER BY timestamp DESC`,
            [userId]
        );

        const logs = rows.map(row => ({
            ...row,
            success: Boolean(row.success)
        }));

        res.json({
            success: true,
            count: logs.length,
            logs: logs
        });
    } catch (error) {
        console.error('Error fetching user logs:', error);
        res.status(500).json({
            error: 'Failed to fetch user logs',
            message: error.message
        });
    }
});

// Get successful logins only
app.get('/api/login-logs/successful', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT 
                id,
                user_id as userId,
                role,
                success,
                timestamp,
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') as timestampReadable,
                ip_address as ipAddress
             FROM login_logs 
             WHERE success = 1
             ORDER BY timestamp DESC`
        );

        const logs = rows.map(row => ({
            ...row,
            success: Boolean(row.success)
        }));

        res.json({
            success: true,
            count: logs.length,
            logs: logs
        });
    } catch (error) {
        console.error('Error fetching successful logs:', error);
        res.status(500).json({
            error: 'Failed to fetch successful logs',
            message: error.message
        });
    }
});

// Get failed logins only
app.get('/api/login-logs/failed', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT 
                id,
                user_id as userId,
                role,
                success,
                timestamp,
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') as timestampReadable,
                ip_address as ipAddress
             FROM login_logs 
             WHERE success = 0
             ORDER BY timestamp DESC`
        );

        const logs = rows.map(row => ({
            ...row,
            success: Boolean(row.success)
        }));

        res.json({
            success: true,
            count: logs.length,
            logs: logs
        });
    } catch (error) {
        console.error('Error fetching failed logs:', error);
        res.status(500).json({
            error: 'Failed to fetch failed logs',
            message: error.message
        });
    }
});

// Get statistics
app.get('/api/login-logs/statistics', async (req, res) => {
    try {
        const [stats] = await pool.execute(
            `SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
                COUNT(DISTINCT user_id) as uniqueUsers
             FROM login_logs`
        );

        // Get statistics by role
        const [roleStats] = await pool.execute(
            `SELECT 
                role,
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
             FROM login_logs
             GROUP BY role`
        );

        const byRole = {};
        roleStats.forEach(stat => {
            byRole[stat.role] = {
                total: parseInt(stat.total),
                successful: parseInt(stat.successful),
                failed: parseInt(stat.failed)
            };
        });

        res.json({
            success: true,
            statistics: {
                total: parseInt(stats[0].total),
                successful: parseInt(stats[0].successful),
                failed: parseInt(stats[0].failed),
                uniqueUsers: parseInt(stats[0].uniqueUsers),
                byRole: byRole
            }
        });
    } catch (error) {
        console.error('Error fetching statistics:', error);
        res.status(500).json({
            error: 'Failed to fetch statistics',
            message: error.message
        });
    }
});

// Clear all logs (Admin only - add authentication in production)
app.delete('/api/login-logs', async (req, res) => {
    try {
        await pool.execute('DELETE FROM login_logs');

        res.json({
            success: true,
            message: 'All login logs cleared successfully'
        });
    } catch (error) {
        console.error('Error clearing logs:', error);
        res.status(500).json({
            error: 'Failed to clear logs',
            message: error.message
        });
    }
});

// ==================== USER MANAGEMENT API ROUTES ====================

// Get all users
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT 
                id,
                user_id as userId,
                role,
                is_default as isDefault,
                created_at as createdAt,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable,
                is_active as isActive
             FROM users 
             WHERE is_active = 1
             ORDER BY is_default DESC, created_at DESC`
        );

        res.json({
            success: true,
            count: rows.length,
            users: rows
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            error: 'Failed to fetch users',
            message: error.message
        });
    }
});

// Get user by ID
app.get('/api/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const [rows] = await pool.execute(
            `SELECT 
                id,
                user_id as userId,
                role,
                is_default as isDefault,
                created_at as createdAt,
                is_active as isActive
             FROM users 
             WHERE user_id = ? AND is_active = 1`,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json({
            success: true,
            user: rows[0]
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            error: 'Failed to fetch user',
            message: error.message
        });
    }
});

// Add new user
app.post('/api/users', async (req, res) => {
    try {
        const { userId, password, role } = req.body;

        // Validation
        if (!userId || !password || !role) {
            return res.status(400).json({
                error: 'Missing required fields: userId, password, role'
            });
        }

        // Validate role
        const validRoles = ['investigator', 'analyst', 'court'];
        if (!validRoles.includes(role)) {
            return res.status(400).json({
                error: 'Invalid role. Allowed roles: investigator, analyst, court'
            });
        }

        // Check if user already exists
        const [existing] = await pool.execute(
            'SELECT id FROM users WHERE user_id = ?',
            [userId]
        );

        if (existing.length > 0) {
            return res.status(409).json({
                error: 'User already exists'
            });
        }

        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert user
        const [result] = await pool.execute(
            `INSERT INTO users (user_id, password_hash, role, is_default) 
             VALUES (?, ?, ?, ?)`,
            [userId, passwordHash, role, false]
        );

        res.json({
            success: true,
            message: 'User added successfully',
            userId: userId,
            id: result.insertId
        });
    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).json({
            error: 'Failed to add user',
            message: error.message
        });
    }
});

// Delete user (soft delete - set is_active to false)
app.delete('/api/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        // Check if user exists
        const [existing] = await pool.execute(
            'SELECT id, is_default FROM users WHERE user_id = ?',
            [userId]
        );

        if (existing.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        // Prevent deleting default users
        if (existing[0].is_default) {
            return res.status(403).json({
                error: 'Cannot delete default users'
            });
        }

        // Soft delete (set is_active to false)
        await pool.execute(
            'UPDATE users SET is_active = 0 WHERE user_id = ?',
            [userId]
        );

        res.json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            error: 'Failed to delete user',
            message: error.message
        });
    }
});

// Verify user credentials (for login) - Returns JWT token
// Security: loginLimiter (5 attempts / 15 min) + accountLockoutCheck applied first
app.post('/api/users/verify', loginLimiter, accountLockoutCheck, async (req, res) => {
    try {
        const { userId, password, role } = req.body;

        if (!userId || !password || !role) {
            return res.status(400).json({
                error: 'Missing required fields',
                valid: false
            });
        }

        // Get user from database
        const [rows] = await pool.execute(
            'SELECT user_id, password_hash, role, is_active FROM users WHERE user_id = ? AND is_active = 1',
            [userId]
        );

        if (rows.length === 0) {
            return res.json({
                valid: false,
                error: 'User not found'
            });
        }

        const user = rows[0];

        // Verify password
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        // Verify role matches
        const roleMatch = user.role === role;

        if (passwordMatch && roleMatch) {
            // Successful login — clear any lockout and detect anomalies
            await clearLockout(user.user_id);
            await detectSuspiciousActivity(user.user_id, req.ip || 'N/A');

            // Generate JWT token
            const token = generateToken(user.user_id, user.role);

            res.json({
                valid: true,
                token: token,
                user: {
                    userId: user.user_id,
                    role: user.role
                }
            });
        } else {
            // Failed login — record the attempt (may trigger lockout)
            await recordFailedAttempt(userId, req.ip || 'N/A');
            res.json({
                valid: false,
                error: passwordMatch ? 'Role mismatch' : 'Invalid password'
            });
        }
    } catch (error) {
        console.error('Error verifying user:', error);
        res.status(500).json({
            error: 'Failed to verify user',
            message: error.message,
            valid: false
        });
    }
});

// ==================== EVIDENCE MANAGEMENT API ROUTES ====================

// Add new evidence (Enhanced with encryption and blockchain support)

// Get all evidence
app.get('/api/evidence', async (req, res) => {
    try {
        const { caseId, investigatorId, status, limit, offset } = req.query;

        let query = `
            SELECT 
                id,
                case_id as caseId,
                file_name as fileName,
                file_size as fileSize,
                file_type as fileType,
                evidence_hash as evidenceHash,
                ipfs_cid as ipfsCID,
                investigator_id as investigatorId,
                status,
                description,
                category,
                tags,
                created_at as createdAt,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable,
                updated_at as updatedAt,
                verified_at as verifiedAt,
                verified_by as verifiedBy
            FROM evidence
            WHERE 1=1
        `;
        const params = [];

        if (caseId) {
            query += ' AND case_id = ?';
            params.push(caseId);
        }
        if (investigatorId) {
            query += ' AND investigator_id = ?';
            params.push(investigatorId);
        }
        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }

        query += ' ORDER BY created_at DESC';

        if (limit) {
            query += ' LIMIT ?';
            params.push(parseInt(limit));
            if (offset) {
                query += ' OFFSET ?';
                params.push(parseInt(offset));
            }
        }

        const [rows] = await pool.query(query, params);

        res.json({
            success: true,
            count: rows.length,
            evidence: rows
        });
    } catch (error) {
        console.error('Error fetching evidence:', error);
        res.status(500).json({
            error: 'Failed to fetch evidence',
            message: error.message
        });
    }
});

// Get evidence statistics (MUST be before /:id route)
app.get('/api/evidence/statistics', async (req, res) => {
    try {
        const [stats] = await pool.execute(
            `SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN status = 'archived' THEN 1 ELSE 0 END) as archived,
                COUNT(DISTINCT case_id) as uniqueCases,
                COUNT(DISTINCT investigator_id) as uniqueInvestigators
            FROM evidence`
        );

        // Get statistics by investigator
        const [investigatorStats] = await pool.execute(
            `SELECT 
                investigator_id as investigatorId,
                COUNT(*) as total
            FROM evidence
            GROUP BY investigator_id
            ORDER BY total DESC
            LIMIT 10`
        );

        // Get statistics by case
        const [caseStats] = await pool.execute(
            `SELECT 
                case_id as caseId,
                COUNT(*) as evidenceCount
            FROM evidence
            GROUP BY case_id
            ORDER BY evidenceCount DESC
            LIMIT 10`
        );

        res.json({
            success: true,
            statistics: {
                total: parseInt(stats[0].total),
                pending: parseInt(stats[0].pending),
                verified: parseInt(stats[0].verified),
                rejected: parseInt(stats[0].rejected),
                archived: parseInt(stats[0].archived),
                uniqueCases: parseInt(stats[0].uniqueCases),
                uniqueInvestigators: parseInt(stats[0].uniqueInvestigators),
                topInvestigators: investigatorStats,
                topCases: caseStats
            }
        });
    } catch (error) {
        console.error('Error fetching evidence statistics:', error);
        res.status(500).json({
            error: 'Failed to fetch statistics',
            message: error.message
        });
    }
});

// Search evidence (MUST be before /:id route)
app.get('/api/evidence/search', async (req, res) => {
    try {
        const { q, caseId, investigatorId, status, category, dateFrom, dateTo } = req.query;

        let query = `
            SELECT 
                id,
                case_id as caseId,
                file_name as fileName,
                file_size as fileSize,
                file_type as fileType,
                evidence_hash as evidenceHash,
                ipfs_cid as ipfsCID,
                investigator_id as investigatorId,
                status,
                description,
                category,
                tags,
                created_at as createdAt,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable
            FROM evidence
            WHERE 1=1
        `;
        const params = [];

        if (q) {
            query += ' AND (file_name LIKE ? OR case_id LIKE ? OR description LIKE ? OR tags LIKE ?)';
            const searchTerm = `%${q}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        if (caseId) {
            query += ' AND case_id = ?';
            params.push(caseId);
        }
        if (investigatorId) {
            query += ' AND investigator_id = ?';
            params.push(investigatorId);
        }
        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }
        if (category) {
            query += ' AND category = ?';
            params.push(category);
        }
        if (dateFrom) {
            query += ' AND created_at >= ?';
            params.push(dateFrom);
        }
        if (dateTo) {
            query += ' AND created_at <= ?';
            params.push(dateTo);
        }

        query += ' ORDER BY created_at DESC LIMIT 100';

        const [rows] = await pool.execute(query, params);

        res.json({
            success: true,
            count: rows.length,
            evidence: rows
        });
    } catch (error) {
        console.error('Error searching evidence:', error);
        res.status(500).json({
            error: 'Failed to search evidence',
            message: error.message
        });
    }
});

// Get evidence by ID
// Get evidence by ID
app.get('/api/evidence/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.query.userId || 'system';
        const role = req.query.role || 'viewer';

        const [rows] = await pool.execute(
            `SELECT 
                id,
                case_id as caseId,
                file_name as fileName,
                file_size as fileSize,
                file_type as fileType,
                evidence_hash as evidenceHash,
                ipfs_cid as ipfsCID,
                investigator_id as investigatorId,
                status,
                description,
                category,
                tags,
                created_at as createdAt,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable,
                updated_at as updatedAt,
                verified_at as verifiedAt,
                verified_by as verifiedBy
            FROM evidence 
            WHERE id = ?`,
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: 'Evidence not found'
            });
        }

        // Log access in chain of custody if it's a user action
        if (userId !== 'system') {
            await pool.execute(
                `INSERT INTO chain_of_custody (evidence_id, action, performed_by, role, description, ip_address) 
                 VALUES (?, 'view', ?, ?, 'Evidence metadata accessed', ?)`,
                [id, userId, role, req.ip || 'N/A']
            );
        }

        res.json({
            success: true,
            evidence: rows[0]
        });
    } catch (error) {
        console.error('Error fetching evidence:', error);
        res.status(500).json({
            error: 'Failed to fetch evidence',
            message: error.message
        });
    }
});

// Get evidence by case ID
app.get('/api/evidence/case/:caseId', async (req, res) => {
    try {
        const { caseId } = req.params;

        const [rows] = await pool.execute(
            `SELECT 
                id,
                case_id as caseId,
                file_name as fileName,
                file_size as fileSize,
                file_type as fileType,
                evidence_hash as evidenceHash,
                ipfs_cid as ipfsCID,
                investigator_id as investigatorId,
                status,
                description,
                category,
                tags,
                created_at as createdAt,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable,
                updated_at as updatedAt,
                verified_at as verifiedAt,
                verified_by as verifiedBy
            FROM evidence 
            WHERE case_id = ?
            ORDER BY created_at DESC`,
            [caseId]
        );

        res.json({
            success: true,
            count: rows.length,
            evidence: rows
        });
    } catch (error) {
        console.error('Error fetching case evidence:', error);
        res.status(500).json({
            error: 'Failed to fetch case evidence',
            message: error.message
        });
    }
});

// Update evidence status
app.put('/api/evidence/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status, verifiedBy, role } = req.body;

        if (!status) {
            return res.status(400).json({
                error: 'Missing required field: status'
            });
        }

        const validStatuses = ['pending', 'verified', 'rejected', 'archived'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({
                error: `Invalid status. Allowed: ${validStatuses.join(', ')}`
            });
        }

        // Get current evidence
        const [current] = await pool.execute(
            'SELECT id, status FROM evidence WHERE id = ?',
            [id]
        );

        if (current.length === 0) {
            return res.status(404).json({
                error: 'Evidence not found'
            });
        }

        // Update evidence
        const updateFields = ['status = ?'];
        const params = [status];

        if (status === 'verified' && verifiedBy) {
            updateFields.push('verified_at = NOW()');
            updateFields.push('verified_by = ?');
            params.push(verifiedBy);
        }

        params.push(id);

        await pool.execute(
            `UPDATE evidence SET ${updateFields.join(', ')}, updated_at = NOW() WHERE id = ?`,
            params
        );

        // Log chain of custody
        await pool.execute(
            `INSERT INTO chain_of_custody (evidence_id, action, performed_by, role, description, ip_address) 
             VALUES (?, 'status_change', ?, ?, ?, ?)`,
            [id, verifiedBy || 'system', role || 'system', `Status changed to: ${status}`, req.ip || 'N/A']
        );

        res.json({
            success: true,
            message: 'Evidence status updated successfully'
        });
    } catch (error) {
        console.error('Error updating evidence status:', error);
        res.status(500).json({
            error: 'Failed to update evidence status',
            message: error.message
        });
    }
});

// Delete evidence (soft delete - set status to archived)
app.delete('/api/evidence/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { performedBy, role } = req.body;

        // Update status to archived instead of deleting
        await pool.execute(
            'UPDATE evidence SET status = ?, updated_at = NOW() WHERE id = ?',
            ['archived', id]
        );

        // Log chain of custody
        if (performedBy) {
            await pool.execute(
                `INSERT INTO chain_of_custody (evidence_id, action, performed_by, role, description, ip_address) 
                 VALUES (?, 'status_change', ?, ?, 'Evidence archived', ?)`,
                [id, performedBy, role || 'admin', req.ip || 'N/A']
            );
        }

        res.json({
            success: true,
            message: 'Evidence archived successfully'
        });
    } catch (error) {
        console.error('Error deleting evidence:', error);
        res.status(500).json({
            error: 'Failed to delete evidence',
            message: error.message
        });
    }
});

// Get chain of custody for evidence
app.get('/api/evidence/:id/chain-of-custody', async (req, res) => {
    try {
        const { id } = req.params;

        const [rows] = await pool.execute(
            `SELECT 
                id,
                action,
                performed_by as performedBy,
                role,
                description,
                ip_address as ipAddress,
                timestamp,
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') as timestampReadable
            FROM chain_of_custody 
            WHERE evidence_id = ?
            ORDER BY timestamp DESC`,
            [id]
        );

        res.json({
            success: true,
            count: rows.length,
            chainOfCustody: rows
        });
    } catch (error) {
        console.error('Error fetching chain of custody:', error);
        res.status(500).json({
            error: 'Failed to fetch chain of custody',
            message: error.message
        });
    }
});

// Add verification record
app.post('/api/evidence/:id/verify', async (req, res) => {
    try {
        const { id } = req.params;
        const { verifiedBy, verificationHash, storedHash, isValid, verificationNotes } = req.body;

        if (!verifiedBy || !verificationHash || !storedHash || isValid === undefined) {
            return res.status(400).json({
                error: 'Missing required fields: verifiedBy, verificationHash, storedHash, isValid'
            });
        }

        // Check if evidence exists
        const [evidence] = await pool.execute(
            'SELECT id, evidence_hash FROM evidence WHERE id = ?',
            [id]
        );

        if (evidence.length === 0) {
            return res.status(404).json({
                error: 'Evidence not found'
            });
        }

        // Insert verification record
        const [result] = await pool.execute(
            `INSERT INTO evidence_verification 
             (evidence_id, verified_by, verification_hash, stored_hash, is_valid, verification_notes) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [id, verifiedBy, verificationHash, storedHash, isValid ? 1 : 0, verificationNotes || null]
        );

        // Update evidence status if valid
        if (isValid) {
            await pool.execute(
                'UPDATE evidence SET status = ?, verified_at = NOW(), verified_by = ? WHERE id = ?',
                ['verified', verifiedBy, id]
            );
        }

        // Blockchain verification feature removed as per request
        // if (isValid) { ... }

        // Log chain of custody
        await pool.execute(
            `INSERT INTO chain_of_custody (evidence_id, action, performed_by, role, description, ip_address) 
             VALUES (?, 'verify', ?, ?, ?, ?)`,
            [id, verifiedBy, 'analyst', `Verification ${isValid ? 'passed' : 'failed'}`, req.ip || 'N/A']
        );

        res.json({
            success: true,
            message: 'Verification record added successfully',
            verificationId: result.insertId
        });
    } catch (error) {
        console.error('Error adding verification:', error);
        res.status(500).json({
            error: 'Failed to add verification record',
            message: error.message
        });
    }
});

// Get verification history for evidence
app.get('/api/evidence/:id/verifications', async (req, res) => {
    try {
        const { id } = req.params;

        const [rows] = await pool.execute(
            `SELECT 
                id,
                verified_by as verifiedBy,
                verification_hash as verificationHash,
                stored_hash as storedHash,
                is_valid as isValid,
                verification_notes as verificationNotes,
                verified_at as verifiedAt,
                DATE_FORMAT(verified_at, '%Y-%m-%d %H:%i:%s') as verifiedAtReadable
            FROM evidence_verification 
            WHERE evidence_id = ?
            ORDER BY verified_at DESC`,
            [id]
        );

        res.json({
            success: true,
            count: rows.length,
            verifications: rows.map(row => ({
                ...row,
                isValid: Boolean(row.isValid)
            }))
        });
    } catch (error) {
        console.error('Error fetching verifications:', error);
        res.status(500).json({
            error: 'Failed to fetch verifications',
            message: error.message
        });
    }
});

// Get system statistics
app.get('/api/statistics', async (req, res) => {
    try {
        const [stats] = await pool.execute(
            `SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN status = 'archived' THEN 1 ELSE 0 END) as archived,
                COUNT(DISTINCT case_id) as uniqueCases,
                COUNT(DISTINCT investigator_id) as uniqueInvestigators
            FROM evidence`
        );

        // Get statistics by investigator
        const [investigatorStats] = await pool.execute(
            `SELECT 
                investigator_id as investigatorId,
                COUNT(*) as total
            FROM evidence
            GROUP BY investigator_id
            ORDER BY total DESC
            LIMIT 10`
        );

        // Get statistics by case
        const [caseStats] = await pool.execute(
            `SELECT 
                case_id as caseId,
                COUNT(*) as evidenceCount
            FROM evidence
            GROUP BY case_id
            ORDER BY evidenceCount DESC
            LIMIT 10`
        );

        res.json({
            success: true,
            statistics: {
                total: parseInt(stats[0].total),
                pending: parseInt(stats[0].pending),
                verified: parseInt(stats[0].verified),
                rejected: parseInt(stats[0].rejected),
                archived: parseInt(stats[0].archived),
                uniqueCases: parseInt(stats[0].uniqueCases),
                uniqueInvestigators: parseInt(stats[0].uniqueInvestigators),
                topInvestigators: investigatorStats,
                topCases: caseStats
            }
        });
    } catch (error) {
        console.error('Error fetching evidence statistics:', error);
        res.status(500).json({
            error: 'Failed to fetch statistics',
            message: error.message
        });
    }
});

// ==================== NEW ENHANCED FEATURES ====================

// Evidence Comments
app.post('/api/evidence/:id/comments', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;
        const userId = req.user.userId;

        if (!comment) {
            return res.status(400).json({ error: 'Comment is required' });
        }

        const [result] = await pool.execute(
            'INSERT INTO evidence_comments (evidence_id, user_id, comment) VALUES (?, ?, ?)',
            [id, userId, comment]
        );

        res.json({
            success: true,
            message: 'Comment added successfully',
            commentId: result.insertId
        });
    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ error: 'Failed to add comment', message: error.message });
    }
});

app.get('/api/evidence/:id/comments', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.execute(
            `SELECT id, user_id as userId, comment, created_at as createdAt, 
             DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable
             FROM evidence_comments WHERE evidence_id = ? ORDER BY created_at DESC`,
            [id]
        );

        res.json({ success: true, comments: rows });
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Failed to fetch comments', message: error.message });
    }
});

// Evidence Versions
app.post('/api/evidence/:id/versions', authenticate, authorize('investigator', 'admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { fileName, fileSize, evidenceHash, ipfsCID, changeDescription } = req.body;
        const userId = req.user.userId;

        // Get current version
        const [current] = await pool.execute('SELECT version FROM evidence WHERE id = ?', [id]);
        const newVersion = (current[0]?.version || 0) + 1;

        // Insert new version
        const [result] = await pool.execute(
            `INSERT INTO evidence_versions 
             (evidence_id, version_number, file_name, file_size, evidence_hash, ipfs_cid, created_by, change_description)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, newVersion, fileName, fileSize, evidenceHash, ipfsCID, userId, changeDescription || null]
        );

        // Update evidence version
        await pool.execute('UPDATE evidence SET version = ? WHERE id = ?', [newVersion, id]);

        res.json({
            success: true,
            message: 'New version created',
            version: { id: result.insertId, versionNumber: newVersion }
        });
    } catch (error) {
        console.error('Error creating version:', error);
        res.status(500).json({ error: 'Failed to create version', message: error.message });
    }
});

app.get('/api/evidence/:id/versions', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.execute(
            `SELECT id, version_number as versionNumber, file_name as fileName, file_size as fileSize,
             evidence_hash as evidenceHash, ipfs_cid as ipfsCID, created_by as createdBy,
             change_description as changeDescription, created_at as createdAt,
             DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAtReadable
             FROM evidence_versions WHERE evidence_id = ? ORDER BY version_number DESC`,
            [id]
        );

        res.json({ success: true, versions: rows });
    } catch (error) {
        console.error('Error fetching versions:', error);
        res.status(500).json({ error: 'Failed to fetch versions', message: error.message });
    }
});

// Evidence Sharing
app.post('/api/evidence/:id/share', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { targetCaseId, notes } = req.body;
        const userId = req.user.userId;

        if (!targetCaseId) {
            return res.status(400).json({ error: 'Target case ID is required' });
        }

        // Get source case ID
        const [evidence] = await pool.execute('SELECT case_id FROM evidence WHERE id = ?', [id]);
        if (evidence.length === 0) {
            return res.status(404).json({ error: 'Evidence not found' });
        }

        const [result] = await pool.execute(
            `INSERT INTO evidence_sharing 
             (evidence_id, source_case_id, target_case_id, shared_by, notes)
             VALUES (?, ?, ?, ?, ?)`,
            [id, evidence[0].case_id, targetCaseId, userId, notes || null]
        );

        res.json({
            success: true,
            message: 'Evidence shared successfully',
            sharingId: result.insertId
        });
    } catch (error) {
        console.error('Error sharing evidence:', error);
        res.status(500).json({ error: 'Failed to share evidence', message: error.message });
    }
});

app.get('/api/evidence/shared/:caseId', async (req, res) => {
    try {
        const { caseId } = req.params;
        const [rows] = await pool.execute(
            `SELECT es.*, e.file_name as fileName, e.evidence_hash as evidenceHash, e.ipfs_cid as ipfsCID
             FROM evidence_sharing es
             JOIN evidence e ON es.evidence_id = e.id
             WHERE es.target_case_id = ? OR es.source_case_id = ?
             ORDER BY es.shared_at DESC`,
            [caseId, caseId]
        );

        res.json({ success: true, sharedEvidence: rows });
    } catch (error) {
        console.error('Error fetching shared evidence:', error);
        res.status(500).json({ error: 'Failed to fetch shared evidence', message: error.message });
    }
});

// Categories
app.get('/api/categories', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM evidence_categories ORDER BY name');
        res.json({ success: true, categories: rows });
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ error: 'Failed to fetch categories', message: error.message });
    }
});

// Advanced Analytics
app.get('/api/analytics/advanced', authenticate, authorize('admin', 'analyst'), async (req, res) => {
    try {
        const { dateFrom, dateTo } = req.query;

        let dateFilter = '';
        const params = [];
        if (dateFrom && dateTo) {
            dateFilter = 'WHERE created_at BETWEEN ? AND ?';
            params.push(dateFrom, dateTo);
        }

        // Evidence trends over time
        const [trends] = await pool.execute(
            `SELECT DATE(created_at) as date, COUNT(*) as count, status
             FROM evidence ${dateFilter}
             GROUP BY DATE(created_at), status
             ORDER BY date DESC
             LIMIT 30`,
            params
        );

        // Category distribution
        const [categories] = await pool.execute(
            `SELECT category, COUNT(*) as count FROM evidence 
             ${dateFilter ? dateFilter.replace('created_at', 'created_at') : 'WHERE category IS NOT NULL'}
             GROUP BY category`,
            params
        );

        // Investigator performance
        const [investigators] = await pool.execute(
            `SELECT investigator_id, COUNT(*) as total, 
             SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified
             FROM evidence ${dateFilter}
             GROUP BY investigator_id
             ORDER BY total DESC`,
            params
        );

        // Status distribution
        const [statusDist] = await pool.execute(
            `SELECT status, COUNT(*) as count FROM evidence ${dateFilter}
             GROUP BY status`,
            params
        );

        res.json({
            success: true,
            analytics: {
                trends: trends,
                categoryDistribution: categories,
                investigatorPerformance: investigators,
                statusDistribution: statusDist
            }
        });
    } catch (error) {
        console.error('Error fetching analytics:', error);
        res.status(500).json({ error: 'Failed to fetch analytics', message: error.message });
    }
});

// PDF Report Generation
app.get('/api/evidence/:id/report', authenticate, async (req, res) => {
    try {
        const { id } = req.params;

        // Get evidence
        const [evidenceRows] = await pool.execute(
            `SELECT * FROM evidence WHERE id = ?`,
            [id]
        );
        if (evidenceRows.length === 0) {
            return res.status(404).json({ error: 'Evidence not found' });
        }

        // Get chain of custody
        const [chainOfCustody] = await pool.execute(
            `SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY timestamp DESC`,
            [id]
        );

        // Get verifications
        const [verifications] = await pool.execute(
            `SELECT * FROM evidence_verification WHERE evidence_id = ? ORDER BY verified_at DESC`,
            [id]
        );

        // Generate PDF
        const reportsDir = path.join(__dirname, '../reports');
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }

        const reportPath = path.join(reportsDir, `evidence_${id}_${Date.now()}.pdf`);
        await generateEvidenceReport(evidenceRows[0], chainOfCustody, verifications, reportPath);

        res.download(reportPath, `evidence_${id}_report.pdf`, (err) => {
            if (err) {
                console.error('Error sending PDF:', err);
            } else {
                // Optionally delete file after sending
                // fs.unlinkSync(reportPath);
            }
        });
    } catch (error) {
        console.error('Error generating report:', error);
        res.status(500).json({ error: 'Failed to generate report', message: error.message });
    }
});

app.get('/api/case/:caseId/report', authenticate, async (req, res) => {
    try {
        const { caseId } = req.params;

        const [evidenceList] = await pool.execute(
            `SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at DESC`,
            [caseId]
        );

        if (evidenceList.length === 0) {
            return res.status(404).json({ error: 'No evidence found for this case' });
        }

        const reportsDir = path.join(__dirname, '../reports');
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }

        const reportPath = path.join(reportsDir, `case_${caseId}_${Date.now()}.pdf`);
        await generateCaseReport(caseId, evidenceList, reportPath);

        res.download(reportPath, `case_${caseId}_report.pdf`);
    } catch (error) {
        console.error('Error generating case report:', error);
        res.status(500).json({ error: 'Failed to generate case report', message: error.message });
    }
});

// Update evidence upload to support encryption and blockchain

// Verify evidence against blockchain (Independent check)
app.post('/api/evidence/verify', async (req, res) => {
    try {
        const { hash, ipfsCID } = req.body; // Can check by hash or CID

        if (!hash && !ipfsCID) {
            return res.status(400).json({ error: 'Hash or IPFS CID is required' });
        }

        // Verify on blockchain
        const verification = await verifyEvidenceOnBlockchain(hash, ipfsCID);

        res.json({
            success: true,
            verified: verification.verified,
            onChainData: verification.onChainData,
            message: verification.message || (verification.verified ? 'Evidence verified on blockchain' : 'Evidence not found on blockchain')
        });

    } catch (error) {
        console.error('Error verifying evidence:', error);
        res.status(500).json({ error: 'Failed to verify evidence', message: error.message });
    }
});

app.post('/api/evidence', async (req, res) => {
    try {
        const { caseId, fileName, fileSize, fileType, evidenceHash, ipfsCID, investigatorId,
            description, category, tags, encrypt, encryptionKey } = req.body;

        if (!caseId || !fileName || !evidenceHash || !ipfsCID || !investigatorId) {
            return res.status(400).json({
                error: 'Missing required fields: caseId, fileName, evidenceHash, ipfsCID, investigatorId'
            });
        }

        // Handle encryption
        let encryptionKeyHash = null;
        let isEncrypted = false;
        if (encrypt && encryptionKey) {
            encryptionKeyHash = hashEncryptionKey(encryptionKey);
            isEncrypted = true;
        }

        // Insert evidence
        const [result] = await pool.execute(
            `INSERT INTO evidence 
             (case_id, file_name, file_size, file_type, evidence_hash, ipfs_cid, investigator_id, 
              description, category, tags, status, is_encrypted, encryption_key_hash) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
            [caseId, fileName, fileSize || 0, fileType || null, evidenceHash, ipfsCID, investigatorId,
                description || null, category || null, tags || null, isEncrypted, encryptionKeyHash]
        );

        const evidenceId = result.insertId;

        // ignore on blockchain (utility handles enabled/disabled check)
        // Get user role if available (from authenticate middleware if used, or default)
        const userRole = req.user ? req.user.role : 'Investigator';
        const bcResult = await storeEvidenceOnBlockchain(evidenceId, caseId, evidenceHash, ipfsCID, userRole);

        if (bcResult.success) {
            console.log('Evidence uploaded to blockchain successfully.');
            // Status remains 'pending' until Analyst verifies it.
        }

        // Log chain of custody
        await pool.execute(
            `INSERT INTO chain_of_custody (evidence_id, action, performed_by, role, description, ip_address) 
             VALUES (?, 'upload', ?, ?, 'Evidence uploaded', ?)`,
            [evidenceId, investigatorId, 'investigator', req.ip || req.connection.remoteAddress || 'N/A']
        );

        // Send notification
        await notifyEvidenceUploaded(investigatorId, caseId, fileName);

        res.json({
            success: true,
            message: 'Evidence added successfully',
            evidence: {
                id: evidenceId,
                caseId: caseId,
                evidenceHash: evidenceHash,
                ipfsCID: ipfsCID,
                isEncrypted: isEncrypted
            }
        });
    } catch (error) {
        console.error('Error adding evidence:', error);
        res.status(500).json({
            error: 'Failed to add evidence',
            message: error.message
        });
    }
});

// Initialize default users (run once to set up default users)
async function initializeDefaultUsers() {
    try {
        const defaultUsers = [
            { userId: 'investigator1', password: 'invest123', role: 'investigator' },
            { userId: 'analyst1', password: 'analyst123', role: 'analyst' },
            { userId: 'court1', password: 'court123', role: 'court' },
            { userId: 'admin1', password: 'admin123', role: 'admin' }
        ];

        for (const user of defaultUsers) {
            // Check if user already exists
            const [existing] = await pool.execute(
                'SELECT id FROM users WHERE user_id = ?',
                [user.userId]
            );

            if (existing.length === 0) {
                // Hash password
                const saltRounds = 10;
                const passwordHash = await bcrypt.hash(user.password, saltRounds);

                // Insert default user
                await pool.execute(
                    `INSERT INTO users (user_id, password_hash, role, is_default) 
                     VALUES (?, ?, ?, ?)`,
                    [user.userId, passwordHash, user.role, true]
                );

                console.log(`✅ Default user created: ${user.userId}`);
            }
        }

        console.log('✅ Default users initialization completed');
    } catch (error) {
        console.error('❌ Error initializing default users:', error);
    }
}

// Initialize default users on server start
initializeDefaultUsers();

// ==================== SECURITY API ROUTES ====================

// GET /api/security/alerts — list security alerts (admin only)
app.get('/api/security/alerts', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { severity, is_resolved, limit = 100 } = req.query;
        let query = `SELECT id, alert_type, user_id as userId, ip_address as ipAddress,
                     description, severity, is_resolved as isResolved,
                     resolved_by as resolvedBy, resolved_at as resolvedAt,
                     DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAt
                     FROM security_alerts WHERE 1=1`;
        const params = [];
        if (severity) { query += ' AND severity = ?'; params.push(severity); }
        if (is_resolved !== undefined) { query += ' AND is_resolved = ?'; params.push(is_resolved === 'true' ? 1 : 0); }
        query += ' ORDER BY created_at DESC LIMIT ?';
        params.push(parseInt(limit));

        const [rows] = await pool.query(query, params);
        res.json({ success: true, count: rows.length, alerts: rows.map(r => ({ ...r, isResolved: Boolean(r.isResolved) })) });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch security alerts', message: error.message });
    }
});

// PUT /api/security/alerts/:id/resolve — mark alert as resolved
app.put('/api/security/alerts/:id/resolve', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const resolvedBy = req.user.userId;
        await pool.execute(
            'UPDATE security_alerts SET is_resolved = 1, resolved_by = ?, resolved_at = NOW() WHERE id = ?',
            [resolvedBy, id]
        );
        res.json({ success: true, message: 'Alert resolved' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to resolve alert', message: error.message });
    }
});

// GET /api/security/lockouts — list locked accounts
app.get('/api/security/lockouts', authenticate, authorize('admin'), async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT user_id as userId, failed_attempts as failedAttempts,
             locked_until as lockedUntil, last_attempt as lastAttempt, ip_address as ipAddress
             FROM account_lockouts
             WHERE locked_until IS NOT NULL AND locked_until > NOW()
             ORDER BY last_attempt DESC`
        );
        res.json({ success: true, count: rows.length, lockouts: rows });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch lockouts', message: error.message });
    }
});

// DELETE /api/security/lockouts/:userId — admin manually unlocks account
app.delete('/api/security/lockouts/:userId', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { userId } = req.params;
        await pool.execute('DELETE FROM account_lockouts WHERE user_id = ?', [userId]);

        // Log the admin action as a chain of custody or security note
        await pool.execute(
            `INSERT INTO security_alerts (alert_type, user_id, ip_address, description, severity, is_resolved, resolved_by, resolved_at)
             VALUES ('account_unlocked', ?, ?, ?, 'low', 1, ?, NOW())`,
            [userId, req.ip || 'N/A', `Admin '${req.user.userId}' manually unlocked account '${userId}'`, req.user.userId]
        );
        res.json({ success: true, message: `Account '${userId}' has been unlocked` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to unlock account', message: error.message });
    }
});

// GET /api/security/blocklist — list blocked IPs
app.get('/api/security/blocklist', authenticate, authorize('admin'), async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT id, ip_address as ipAddress, reason,
             blocked_by as blockedBy,
             DATE_FORMAT(blocked_at, '%Y-%m-%d %H:%i:%s') as blockedAt,
             expires_at as expiresAt
             FROM ip_blocklist ORDER BY blocked_at DESC`
        );
        res.json({ success: true, count: rows.length, blocklist: rows });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch blocklist', message: error.message });
    }
});

// POST /api/security/blocklist — add IP to blocklist
app.post('/api/security/blocklist', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { ipAddress, reason, expiresAt } = req.body;
        if (!ipAddress) return res.status(400).json({ error: 'ipAddress is required' });

        // Basic IP format validation
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^[0-9a-fA-F:]{2,39}$/;
        if (!ipv4Regex.test(ipAddress) && !ipv6Regex.test(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address format' });
        }

        await pool.execute(
            `INSERT INTO ip_blocklist (ip_address, reason, blocked_by, expires_at)
             VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE reason=VALUES(reason), expires_at=VALUES(expires_at)`,
            [ipAddress, reason || null, req.user.userId, expiresAt || null]
        );
        res.json({ success: true, message: `IP ${ipAddress} added to blocklist` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add IP to blocklist', message: error.message });
    }
});

// DELETE /api/security/blocklist/:id — remove IP from blocklist
app.delete('/api/security/blocklist/:id', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await pool.execute('DELETE FROM ip_blocklist WHERE id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Blocklist entry not found' });
        res.json({ success: true, message: 'IP removed from blocklist' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove IP from blocklist', message: error.message });
    }
});

// GET /api/security/audit-report — combined security summary
app.get('/api/security/audit-report', authenticate, authorize('admin'), async (req, res) => {
    try {
        const [[alertStats]] = await pool.execute(
            `SELECT COUNT(*) as total,
             SUM(CASE WHEN is_resolved = 0 THEN 1 ELSE 0 END) as unresolved,
             SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
             SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
             SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
             SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
             FROM security_alerts`
        );
        const [[lockoutStats]] = await pool.execute(
            `SELECT COUNT(*) as total,
             SUM(CASE WHEN locked_until IS NOT NULL AND locked_until > NOW() THEN 1 ELSE 0 END) as active
             FROM account_lockouts`
        );
        const [[blocklistStats]] = await pool.execute(
            `SELECT COUNT(*) as total FROM ip_blocklist WHERE (expires_at IS NULL OR expires_at > NOW())`
        );
        const [recentAlerts] = await pool.execute(
            `SELECT alert_type, description, severity, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as createdAt
             FROM security_alerts WHERE is_resolved = 0 ORDER BY created_at DESC LIMIT 10`
        );
        res.json({
            success: true,
            report: {
                generatedAt: new Date().toISOString(),
                alerts: alertStats,
                lockouts: lockoutStats,
                blocklist: blocklistStats,
                recentUnresolvedAlerts: recentAlerts
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate audit report', message: error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

// Start server
app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('🚀 Backend API Server Started!');
    console.log('='.repeat(60));
    console.log(`📡 API Server running at: http://localhost:${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log('='.repeat(60));
    console.log('\n💡 API Endpoints:');
    console.log('   POST   /api/login-logs              - Insert login log');
    console.log('   GET    /api/login-logs              - Get all logs');
    console.log('   GET    /api/login-logs/user/:userId - Get logs by user');
    console.log('   GET    /api/login-logs/successful   - Get successful logs');
    console.log('   GET    /api/login-logs/failed       - Get failed logs');
    console.log('   GET    /api/login-logs/statistics   - Get statistics');
    console.log('   DELETE /api/login-logs              - Clear all logs');
    console.log('\n💡 User Management Endpoints:');
    console.log('   GET    /api/users                  - Get all users');
    console.log('   GET    /api/users/:userId         - Get user by ID');
    console.log('   POST   /api/users                  - Add new user');
    console.log('   DELETE /api/users/:userId         - Delete user');
    console.log('   POST   /api/users/verify          - Verify credentials');
    console.log('\n💡 Evidence Management Endpoints:');
    console.log('   POST   /api/evidence              - Add new evidence');
    console.log('   GET    /api/evidence             - Get all evidence');
    console.log('   GET    /api/evidence/:id         - Get evidence by ID');
    console.log('   GET    /api/evidence/case/:caseId - Get evidence by case ID');
    console.log('   PUT    /api/evidence/:id/status   - Update evidence status');
    console.log('   DELETE /api/evidence/:id         - Archive evidence');
    console.log('   GET    /api/evidence/:id/chain-of-custody - Get chain of custody');
    console.log('   POST   /api/evidence/:id/verify   - Add verification record');
    console.log('   GET    /api/evidence/:id/verifications - Get verification history');
    console.log('   GET    /api/evidence/statistics   - Get evidence statistics');
    console.log('   GET    /api/evidence/search       - Search evidence');
    console.log('\n🔐 Security Endpoints (Admin only):');
    console.log('   GET    /api/security/alerts            - List security alerts');
    console.log('   PUT    /api/security/alerts/:id/resolve - Resolve alert');
    console.log('   GET    /api/security/lockouts          - List locked accounts');
    console.log('   DELETE /api/security/lockouts/:userId  - Unlock account');
    console.log('   GET    /api/security/blocklist         - List blocked IPs');
    console.log('   POST   /api/security/blocklist         - Block an IP');
    console.log('   DELETE /api/security/blocklist/:id     - Unblock an IP');
    console.log('   GET    /api/security/audit-report      - Full security report');
    console.log('='.repeat(60) + '\n');

    // Print Blockchain History
    printBlockchainHistory();
});

// Graceful shutdown
// process.on('SIGINT', async () => {
//     console.log('\n\n🛑 Shutting down server...');
//     await pool.end();
//     process.exit(0);
// });

console.log('DEBUG: Reached end of server.js');

