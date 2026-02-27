/**
 * Enhanced Features API Client
 * Handles all new enhanced features
 */

const EnhancedFeatures = {
    getApiBaseUrl: function() {
        return (typeof CONFIG !== 'undefined' && CONFIG.API && CONFIG.API.BASE_URL) 
            ? CONFIG.API.BASE_URL 
            : 'http://localhost:3000/api';
    },

    get API_BASE_URL() {
        return this.getApiBaseUrl();
    },

    // JWT Token Management
    getToken: () => {
        return localStorage.getItem('jwt_token');
    },

    setToken: (token) => {
        localStorage.setItem('jwt_token', token);
    },

    clearToken: () => {
        localStorage.removeItem('jwt_token');
    },

    // Get auth headers
    getAuthHeaders: function() {
        const token = this.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    },

    // Evidence Comments
    addComment: async function(evidenceId, comment) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/${evidenceId}/comments`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...EnhancedFeatures.getAuthHeaders()
                },
                body: JSON.stringify({ comment })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to add comment');
            }

            return await response.json();
        } catch (error) {
            console.error('Error adding comment:', error);
            throw error;
        }
    },

    getComments: async function(evidenceId) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/${evidenceId}/comments`);
            if (!response.ok) throw new Error('Failed to fetch comments');
            const data = await response.json();
            return data.comments || [];
        } catch (error) {
            console.error('Error fetching comments:', error);
            throw error;
        }
    },

    // Evidence Versions
    createVersion: async function(evidenceId, versionData) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/${evidenceId}/versions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...EnhancedFeatures.getAuthHeaders()
                },
                body: JSON.stringify(versionData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to create version');
            }

            return await response.json();
        } catch (error) {
            console.error('Error creating version:', error);
            throw error;
        }
    },

    getVersions: async function(evidenceId) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/${evidenceId}/versions`);
            if (!response.ok) throw new Error('Failed to fetch versions');
            const data = await response.json();
            return data.versions || [];
        } catch (error) {
            console.error('Error fetching versions:', error);
            throw error;
        }
    },

    // Evidence Sharing
    shareEvidence: async function(evidenceId, targetCaseId, notes) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/${evidenceId}/share`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...EnhancedFeatures.getAuthHeaders()
                },
                body: JSON.stringify({ targetCaseId, notes })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to share evidence');
            }

            return await response.json();
        } catch (error) {
            console.error('Error sharing evidence:', error);
            throw error;
        }
    },

    getSharedEvidence: async function(caseId) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/shared/${encodeURIComponent(caseId)}`);
            if (!response.ok) throw new Error('Failed to fetch shared evidence');
            const data = await response.json();
            return data.sharedEvidence || [];
        } catch (error) {
            console.error('Error fetching shared evidence:', error);
            throw error;
        }
    },

    // Categories
    getCategories: async function() {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/categories`);
            if (!response.ok) throw new Error('Failed to fetch categories');
            const data = await response.json();
            return data.categories || [];
        } catch (error) {
            console.error('Error fetching categories:', error);
            throw error;
        }
    },

    // Advanced Analytics
    getAdvancedAnalytics: async function(dateFrom, dateTo) {
        try {
            const params = new URLSearchParams();
            if (dateFrom) params.append('dateFrom', dateFrom);
            if (dateTo) params.append('dateTo', dateTo);

            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/analytics/advanced?${params.toString()}`, {
                headers: EnhancedFeatures.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch analytics');
            const data = await response.json();
            return data.analytics || {};
        } catch (error) {
            console.error('Error fetching analytics:', error);
            throw error;
        }
    },

    // PDF Reports
    generateEvidenceReport: async function(evidenceId) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/evidence/${evidenceId}/report`, {
                headers: EnhancedFeatures.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to generate report');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `evidence_${evidenceId}_report.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            return { success: true };
        } catch (error) {
            console.error('Error generating report:', error);
            throw error;
        }
    },

    generateCaseReport: async function(caseId) {
        try {
            const response = await fetch(`${EnhancedFeatures.getApiBaseUrl()}/case/${encodeURIComponent(caseId)}/report`, {
                headers: EnhancedFeatures.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to generate case report');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `case_${caseId}_report.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            return { success: true };
        } catch (error) {
            console.error('Error generating case report:', error);
            throw error;
        }
    },

    // File Encryption (client-side)
    generateEncryptionKey: function() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    },

    encryptFile: async function(file, key) {
        try {
            // Import key
            const keyData = new Uint8Array(key.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );

            // Generate IV
            const iv = crypto.getRandomValues(new Uint8Array(12));

            // Read file
            const fileBuffer = await file.arrayBuffer();

            // Encrypt
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                cryptoKey,
                fileBuffer
            );

            // Combine IV and encrypted data
            const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encryptedBuffer), iv.length);

            return new Blob([combined], { type: 'application/octet-stream' });
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('File encryption failed: ' + error.message);
        }
    }
};

