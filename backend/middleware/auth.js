/**
 * JWT Authentication Middleware
 */

const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const config = require('../config');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Create connection pool
const pool = mysql.createPool(config.database);

/**
 * Generate JWT token
 */
function generateToken(userId, role) {
    return jwt.sign(
        { userId, role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

/**
 * Authentication middleware
 */
async function authenticate(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                error: 'No token provided',
                message: 'Authorization header must be: Bearer <token>' 
            });
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        
        // Verify token
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ 
                error: 'Invalid or expired token' 
            });
        }

        // Check if user exists and is active
        const [users] = await pool.execute(
            'SELECT user_id, role, is_active FROM users WHERE user_id = ? AND is_active = 1',
            [decoded.userId]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                error: 'User not found or inactive' 
            });
        }

        // Attach user info to request
        req.user = {
            userId: decoded.userId,
            role: decoded.role
        };

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ 
            error: 'Authentication failed',
            message: error.message 
        });
    }
}

/**
 * Role-based authorization middleware
 */
function authorize(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                error: 'Authentication required' 
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: 'Insufficient permissions',
                message: `Required role: ${allowedRoles.join(' or ')}` 
            });
        }

        next();
    };
}

module.exports = {
    generateToken,
    verifyToken,
    authenticate,
    authorize,
    JWT_SECRET,
    JWT_EXPIRES_IN
};

