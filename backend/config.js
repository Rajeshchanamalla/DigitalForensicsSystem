/**
 * Backend Configuration
 * MySQL Database Configuration
 */

module.exports = {
    // MySQL Database Configuration
    database: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || 'Rajesh@512',
        database: process.env.DB_NAME || 'forensic_system_db',
        port: process.env.DB_PORT || 3306,
        connectionLimit: 10,
        waitForConnections: true,
        queueLimit: 0
    },

    // Server Configuration
    server: {
        port: process.env.PORT || 3000,
        cors: {
            origin: '*', // Allow all origins (change in production)
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization']
        }
    }
};

