/**
 * Evidence API Client
 * Handles all evidence-related API calls to the backend
 */

const EvidenceAPI = {
    API_BASE_URL: CONFIG.API.BASE_URL || 'http://localhost:3000/api',

    // Add new evidence
    addEvidence: async function(evidenceData) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(evidenceData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to add evidence');
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error adding evidence:', error);
            throw error;
        }
    },

    // Get all evidence
    getAllEvidence: async function(filters = {}) {
        try {
            const queryParams = new URLSearchParams();
            if (filters.caseId) queryParams.append('caseId', filters.caseId);
            if (filters.investigatorId) queryParams.append('investigatorId', filters.investigatorId);
            if (filters.status) queryParams.append('status', filters.status);
            if (filters.limit) queryParams.append('limit', filters.limit);
            if (filters.offset) queryParams.append('offset', filters.offset);

            const url = `${this.API_BASE_URL}/evidence${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.evidence || [];
        } catch (error) {
            console.error('Error fetching evidence:', error);
            throw error;
        }
    },

    // Get evidence by ID
    getEvidenceById: async function(id) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/${id}`);

            if (!response.ok) {
                if (response.status === 404) {
                    return null;
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.evidence;
        } catch (error) {
            console.error('Error fetching evidence:', error);
            throw error;
        }
    },

    // Get evidence by case ID
    getEvidenceByCaseId: async function(caseId) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/case/${encodeURIComponent(caseId)}`);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.evidence || [];
        } catch (error) {
            console.error('Error fetching case evidence:', error);
            throw error;
        }
    },

    // Update evidence status
    updateEvidenceStatus: async function(id, status, verifiedBy = null, role = null) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/${id}/status`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    status: status,
                    verifiedBy: verifiedBy,
                    role: role
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to update evidence status');
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error updating evidence status:', error);
            throw error;
        }
    },

    // Delete/Archive evidence
    deleteEvidence: async function(id, performedBy = null, role = null) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    performedBy: performedBy,
                    role: role
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to delete evidence');
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error deleting evidence:', error);
            throw error;
        }
    },

    // Get chain of custody
    getChainOfCustody: async function(id) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/${id}/chain-of-custody`);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.chainOfCustody || [];
        } catch (error) {
            console.error('Error fetching chain of custody:', error);
            throw error;
        }
    },

    // Add verification record
    addVerification: async function(id, verificationData) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/${id}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(verificationData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to add verification');
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error adding verification:', error);
            throw error;
        }
    },

    // Get verification history
    getVerifications: async function(id) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/${id}/verifications`);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.verifications || [];
        } catch (error) {
            console.error('Error fetching verifications:', error);
            throw error;
        }
    },

    // Get evidence statistics
    getStatistics: async function() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/evidence/statistics`);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.statistics || {};
        } catch (error) {
            console.error('Error fetching statistics:', error);
            throw error;
        }
    },

    // Search evidence
    searchEvidence: async function(searchParams) {
        try {
            const queryParams = new URLSearchParams();
            if (searchParams.q) queryParams.append('q', searchParams.q);
            if (searchParams.caseId) queryParams.append('caseId', searchParams.caseId);
            if (searchParams.investigatorId) queryParams.append('investigatorId', searchParams.investigatorId);
            if (searchParams.status) queryParams.append('status', searchParams.status);
            if (searchParams.category) queryParams.append('category', searchParams.category);
            if (searchParams.dateFrom) queryParams.append('dateFrom', searchParams.dateFrom);
            if (searchParams.dateTo) queryParams.append('dateTo', searchParams.dateTo);

            const url = `${this.API_BASE_URL}/evidence/search${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.evidence || [];
        } catch (error) {
            console.error('Error searching evidence:', error);
            throw error;
        }
    }
};

