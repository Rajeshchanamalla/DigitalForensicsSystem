// Configuration file for the Digital Forensic System
// API URL: reads from env-config.js (injected at deploy time), falls back to localhost
const _runtimeConfig = (typeof window !== 'undefined' && window.APP_CONFIG) ? window.APP_CONFIG : {};

const CONFIG = {
    // User roles
    ROLES: {
        INVESTIGATOR: 'investigator',
        ANALYST: 'analyst',
        COURT: 'court',
        ADMIN: 'admin'
    },

    // Demo users (for initial review)
    USERS: {
        'investigator1': { password: 'invest123', role: 'investigator' },
        'analyst1': { password: 'analyst123', role: 'analyst' },
        'court1': { password: 'court123', role: 'court' },
        'admin1': { password: 'admin123', role: 'admin' }
    },

    // Backend API Configuration
    // In production: reads from env-config.js which is generated at Vercel deploy time
    API: {
        BASE_URL: _runtimeConfig.API_BASE_URL || 'http://localhost:3000/api'
    },

    // IPFS Configuration
    // Uses Pinata if keys are configured (production), falls back to local IPFS (development)
    IPFS: {
        // Auto-detect: use Pinata in production, local IPFS in development
        API_URL: (_runtimeConfig.PINATA_API_KEY)
            ? 'https://api.pinata.cloud/pinning/pinFileToIPFS'
            : 'http://127.0.0.1:5001/api/v0/add',
        PINATA_API_KEY: _runtimeConfig.PINATA_API_KEY || '',
        PINATA_SECRET_KEY: _runtimeConfig.PINATA_SECRET_KEY || '',
        GATEWAY: _runtimeConfig.IPFS_GATEWAY || 'http://127.0.0.1:8080/ipfs/'
    }
};

// User Management System (MySQL API)
const UserManagement = {
    // Get API base URL
    getApiBaseUrl: function () {
        return 'http://localhost:3000/api'; // Direct URL - can be changed if needed
    },

    // Get all users from MySQL database
    getAllUsers: async function () {
        try {
            const response = await fetch(`${UserManagement.getApiBaseUrl()}/users`);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Convert array to object format for compatibility
            const usersObj = {};
            data.users.forEach(user => {
                usersObj[user.userId] = {
                    role: user.role,
                    isDefault: user.isDefault,
                    createdAt: user.createdAt
                };
            });

            return usersObj;
        } catch (error) {
            console.error('Error fetching users:', error);
            // Fallback to empty object if API fails
            return {};
        }
    },

    // Add new user to MySQL database
    addUser: async function (userId, password, role) {
        try {
            const response = await fetch(`${UserManagement.getApiBaseUrl()}/users`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    userId: userId,
                    password: password,
                    role: role
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to add user');
            }

            const data = await response.json();
            console.log('User added:', data);
            return data;
        } catch (error) {
            console.error('Error adding user:', error);
            throw error;
        }
    },

    // Delete user from MySQL database
    deleteUser: async function (userId) {
        try {
            const response = await fetch(`${UserManagement.getApiBaseUrl()}/users/${encodeURIComponent(userId)}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to delete user');
            }

            const data = await response.json();
            console.log('User deleted:', data);
            return data;
        } catch (error) {
            console.error('Error deleting user:', error);
            throw error;
        }
    },

    // Check if user exists in MySQL database
    userExists: async function (userId) {
        try {
            const response = await fetch(`${UserManagement.getApiBaseUrl()}/users/${encodeURIComponent(userId)}`);
            return response.ok;
        } catch (error) {
            console.error('Error checking user:', error);
            return false;
        }
    },

    // Get user by ID from MySQL database
    getUser: async function (userId) {
        try {
            const response = await fetch(`${UserManagement.getApiBaseUrl()}/users/${encodeURIComponent(userId)}`);

            if (!response.ok) {
                return null;
            }

            const data = await response.json();
            return {
                userId: data.user.userId,
                role: data.user.role,
                isDefault: data.user.isDefault
            };
        } catch (error) {
            console.error('Error fetching user:', error);
            return null;
        }
    },

    // Verify user credentials (for login)
    verifyUser: async function (userId, password, role) {
        try {
            const response = await fetch(`${UserManagement.getApiBaseUrl()}/users/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    userId: userId,
                    password: password,
                    role: role
                })
            });

            if (!response.ok) {
                return { valid: false, error: 'Verification failed' };
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error verifying user:', error);
            return { valid: false, error: error.message };
        }
    }
};

// Login Logs Database (simulated database using localStorage)
const LoginLogs = {
    STORAGE_KEY: 'login_logs',

    // Log login attempt
    logLogin: (userId, role, success, ipAddress = null) => {
        const logs = LoginLogs.getAllLogs();
        const logEntry = {
            id: logs.length + 1,
            userId: userId,
            role: role,
            success: success,
            timestamp: new Date().toISOString(),
            timestampReadable: new Date().toLocaleString(),
            ipAddress: ipAddress || 'N/A'
        };
        logs.push(logEntry);
        localStorage.setItem(LoginLogs.STORAGE_KEY, JSON.stringify(logs));
        return logEntry;
    },

    // Get all login logs
    getAllLogs: () => {
        return JSON.parse(localStorage.getItem(LoginLogs.STORAGE_KEY) || '[]');
    },

    // Get logs by user ID
    getLogsByUser: (userId) => {
        const logs = LoginLogs.getAllLogs();
        return logs.filter(log => log.userId === userId);
    },

    // Get successful logins
    getSuccessfulLogins: () => {
        const logs = LoginLogs.getAllLogs();
        return logs.filter(log => log.success === true);
    },

    // Get failed logins
    getFailedLogins: () => {
        const logs = LoginLogs.getAllLogs();
        return logs.filter(log => log.success === false);
    },

    // Get recent logs (last N entries)
    getRecentLogs: (count = 50) => {
        const logs = LoginLogs.getAllLogs();
        return logs.slice(-count).reverse();
    },

    // Clear all logs
    clearLogs: () => {
        localStorage.removeItem(LoginLogs.STORAGE_KEY);
    }
};

// Session management
const Session = {
    getCurrentUser: () => {
        return JSON.parse(localStorage.getItem('currentUser') || 'null');
    },
    setCurrentUser: (user) => {
        localStorage.setItem('currentUser', JSON.stringify(user));
    },
    clearSession: () => {
        localStorage.removeItem('currentUser');
    },
    isAuthenticated: () => {
        return Session.getCurrentUser() !== null;
    }
};

// Simulated Blockchain Storage (using localStorage)
const BlockchainStorage = {
    // Storage key for evidence records
    STORAGE_KEY: 'blockchain_evidence',

    // Get all evidence records
    getAllEvidence: () => {
        return JSON.parse(localStorage.getItem(BlockchainStorage.STORAGE_KEY) || '[]');
    },

    // Add evidence record
    addEvidence: (caseId, evidenceHash, ipfsCID, investigator) => {
        const evidences = BlockchainStorage.getAllEvidence();
        const newEvidence = {
            index: evidences.length,
            caseId: caseId,
            evidenceHash: evidenceHash,
            ipfsCID: ipfsCID,
            timestamp: Date.now(),
            investigator: investigator || 'Unknown'
        };
        evidences.push(newEvidence);
        localStorage.setItem(BlockchainStorage.STORAGE_KEY, JSON.stringify(evidences));
        return newEvidence;
    },

    // Get evidence by index
    getEvidence: (index) => {
        const evidences = BlockchainStorage.getAllEvidence();
        if (index >= 0 && index < evidences.length) {
            return evidences[index];
        }
        return null;
    },

    // Get evidence count
    getEvidenceCount: () => {
        return BlockchainStorage.getAllEvidence().length;
    },

    // Get evidence by case ID
    getEvidenceByCaseId: (caseId) => {
        const evidences = BlockchainStorage.getAllEvidence();
        return evidences.filter(e => e.caseId.toLowerCase() === caseId.toLowerCase());
    }
};
