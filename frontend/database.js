/**
 * MySQL Database API Client
 * This replaces IndexedDB and connects to MySQL backend via REST API
 */

const Database = {
    API_BASE_URL: CONFIG.API.BASE_URL || 'http://localhost:3000/api',

    // Insert login log (POST /api/login-logs)
    insertLoginLog: async function(userId, role, success, ipAddress = null) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    userId: userId,
                    role: role,
                    success: success,
                    ipAddress: ipAddress
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('Login log inserted:', data);
            return data.id;
        } catch (error) {
            console.error('Error inserting login log:', error);
            throw error;
        }
    },

    // Get all login logs (GET /api/login-logs)
    getAllLogs: async function() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.logs || [];
        } catch (error) {
            console.error('Error fetching login logs:', error);
            throw error;
        }
    },

    // Get logs by user ID (GET /api/login-logs/user/:userId)
    getLogsByUser: async function(userId) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs/user/${encodeURIComponent(userId)}`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.logs || [];
        } catch (error) {
            console.error('Error fetching user logs:', error);
            throw error;
        }
    },

    // Get successful logins (GET /api/login-logs/successful)
    getSuccessfulLogins: async function() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs/successful`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.logs || [];
        } catch (error) {
            console.error('Error fetching successful logs:', error);
            throw error;
        }
    },

    // Get failed logins (GET /api/login-logs/failed)
    getFailedLogins: async function() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs/failed`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.logs || [];
        } catch (error) {
            console.error('Error fetching failed logs:', error);
            throw error;
        }
    },

    // Get recent logs (GET /api/login-logs with limit)
    getRecentLogs: async function(limit = 50) {
        try {
            const logs = await this.getAllLogs();
            return logs.slice(0, limit);
        } catch (error) {
            console.error('Error fetching recent logs:', error);
            throw error;
        }
    },

    // Clear all logs (DELETE /api/login-logs)
    clearAllLogs: async function() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs`, {
                method: 'DELETE'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('All login logs cleared');
            return data;
        } catch (error) {
            console.error('Error clearing logs:', error);
            throw error;
        }
    },

    // Get statistics (GET /api/login-logs/statistics)
    getStatistics: async function() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/login-logs/statistics`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.statistics || {
                total: 0,
                successful: 0,
                failed: 0,
                uniqueUsers: 0,
                byRole: {}
            };
        } catch (error) {
            console.error('Error fetching statistics:', error);
            throw error;
        }
    },

    // Initialize database (no-op for API, kept for compatibility)
    init: async function() {
        // Check if API is available
        try {
            const response = await fetch(`${this.API_BASE_URL}/health`);
            if (response.ok) {
                console.log('✅ Database API connected successfully!');
                return true;
            } else {
                throw new Error('API health check failed');
            }
        } catch (error) {
            console.error('❌ Database API connection failed:', error);
            console.error('   Please make sure the backend server is running:');
            console.error('   Run: npm run backend');
            throw error;
        }
    }
};

// Initialize database connection on load
if (typeof window !== 'undefined') {
    window.addEventListener('DOMContentLoaded', () => {
        Database.init().catch(err => {
            console.error('Failed to initialize database:', err);
        });
    });
}
