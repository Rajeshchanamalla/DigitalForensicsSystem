/**
 * Express Backend Server with MySQL Integration
 * API Server for Digital Forensic System
 */

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const config = require('./config');

const app = express();
const PORT = config.server.port;

// Middleware
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

// Verify user credentials (for login)
app.post('/api/users/verify', async (req, res) => {
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
            res.json({
                valid: true,
                user: {
                    userId: user.user_id,
                    role: user.role
                }
            });
        } else {
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
    console.log('='.repeat(60) + '\n');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n\n🛑 Shutting down server...');
    await pool.end();
    process.exit(0);
});

