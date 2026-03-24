const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function clearEvidence() {
    console.log('\n🧹 Starting Evidence Cleanup Process...');
    let connection;
    try {
        console.log('🔗 Connecting to Database (' + (process.env.DB_HOST || 'localhost') + ')...');
        connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'railway',
            port: process.env.DB_PORT || 3306,
            ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined
        });

        console.log('✅ Connected. Deleting all evidence records...');
        
        // Disable foreign key checks temporarily to safely truncate linked tables
        await connection.query('SET FOREIGN_KEY_CHECKS = 0');
        
        const tablesToClear = [
            'chain_of_custody',
            'evidence_verification',
            'evidence_comments',
            'evidence_sharing',
            'evidence_versions',
            'blockchain_transactions',
            'evidence'
        ];

        for (const table of tablesToClear) {
            try {
                await connection.query(`TRUNCATE TABLE ${table}`);
                console.log(`  🗑️ Cleared exactly: ${table}`);
            } catch (err) {
                // If table doesn't exist, ignore
            }
        }
        
        await connection.query('SET FOREIGN_KEY_CHECKS = 1');
        console.log('\n✅ Database Evidence Cleared Successfully! (User accounts were safely kept)');
    } catch (error) {
        console.error('\n❌ Database Error:', error.message);
    } finally {
        if (connection) await connection.end();
    }

    // 2. Clear Blockchain Data
    console.log('\n🔗 Clearing Local Blockchain State...');
    const bcDataFiles = [
        path.join(__dirname, '..', 'backend', 'blockchain-data.json'),
        path.join(__dirname, '..', 'blockchain-data.json')
    ];

    let bcCleared = false;
    for (const file of bcDataFiles) {
        if (fs.existsSync(file)) {
            fs.unlinkSync(file);
            console.log(`  🗑️ Deleted: ${file}`);
            bcCleared = true;
        }
    }

    const chainDataDir = path.join(__dirname, '..', 'chain-data');
    if (fs.existsSync(chainDataDir)) {
        fs.rmSync(chainDataDir, { recursive: true, force: true });
        console.log(`  🗑️ Deleted entire Ganache chain-data folder.`);
        bcCleared = true;
    }

    if (!bcCleared) {
        console.log('  ℹ️ No local blockchain data found (already clean).');
    } else {
        console.log('✅ Local Blockchain Cleared! A fresh smart contract will deploy on next start.');
    }

    console.log('\n🎉 CLEARED EVERYTHING! Your project is now a clean slate for the panel demo.');
    process.exit(0);
}

clearEvidence();
