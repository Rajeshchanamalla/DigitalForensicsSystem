require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

// CORS origins: allow Vercel frontend URL in production, any origin locally
const allowedOrigins = process.env.FRONTEND_URL
    ? [process.env.FRONTEND_URL, 'http://localhost:8000', 'http://localhost:3000']
    : '*';

module.exports = {
    // MySQL Database Configuration
    database: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || 'Rajesh@512',
        database: process.env.DB_NAME || 'forensic_system_db',
        port: parseInt(process.env.DB_PORT) || 3306,
        connectionLimit: 10,
        waitForConnections: true,
        queueLimit: 0,
        ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined
    },

    // Server Configuration
    server: {
        port: process.env.PORT || 3000,
        cors: {
            origin: allowedOrigins,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            credentials: true
        }
    }
};

