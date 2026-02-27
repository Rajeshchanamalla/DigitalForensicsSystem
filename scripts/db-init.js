/**
 * Database Initialization Script
 * Reads database/init.sql and runs it against the configured MySQL database.
 * Run: node scripts/db-init.js
 *
 * Uses env vars: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

async function initDatabase() {
    console.log('🗄️  Connecting to MySQL...');
    console.log(`   Host: ${process.env.DB_HOST || 'localhost'}`);
    console.log(`   DB:   ${process.env.DB_NAME || 'forensic_system_db'}`);

    const connection = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || 'Rajesh@512',
        port: parseInt(process.env.DB_PORT) || 3306,
        ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
        multipleStatements: true   // Required to run the full SQL file
    });

    try {
        const sqlPath = path.resolve(__dirname, '../database/init.sql');
        const sql = fs.readFileSync(sqlPath, 'utf8');

        console.log('📋 Running init.sql...');
        await connection.query(sql);
        console.log('✅ Database initialized successfully!');
        console.log('   All tables created (or already exist).');
    } catch (error) {
        console.error('❌ Database initialization failed:', error.message);
        process.exit(1);
    } finally {
        await connection.end();
    }
}

initDatabase().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
