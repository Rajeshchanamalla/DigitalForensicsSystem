const UserManagement = {
    // Get all users
    getAllUsers: async () => {
        try {
            const token = Session.getToken();
            const response = await fetch(`${CONFIG.API.BASE_URL}/users`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch users');
            }

            const data = await response.json();
            // Convert array to object keyed by userId for existing frontend logic compatibility
            const usersMap = {};
            if (data.users) {
                data.users.forEach(u => {
                    usersMap[u.userId] = u;
                });
            }
            return usersMap;
        } catch (error) {
            console.error('Error fetching users:', error);
            throw error;
        }
    },

    // Check if user exists (Frontend helper, can rely on getAllUsers or add dedicated API)
    userExists: async (userId) => {
        const users = await UserManagement.getAllUsers();
        return !!users[userId];
    },

    // Add new user
    addUser: async (userId, password, role) => {
        try {
            const token = Session.getToken();
            const response = await fetch(`${CONFIG.API.BASE_URL}/users`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ userId, password, role })
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Failed to add user');
            }
            return data;
        } catch (error) {
            console.error('Error adding user:', error);
            throw error;
        }
    },

    // Delete user
    deleteUser: async (userId) => {
        try {
            const token = Session.getToken();
            const response = await fetch(`${CONFIG.API.BASE_URL}/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Failed to delete user');
            }
            return data;
        } catch (error) {
            console.error('Error deleting user:', error);
            throw error;
        }
    }
};
