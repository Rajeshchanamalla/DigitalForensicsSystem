/**
 * Simple HTTP Server for Digital Forensic System
 * Node.js server that serves the frontend files
 * Run: node server.js
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const PORT = 8000;
const FRONTEND_DIR = path.join(__dirname, 'frontend');

// MIME types for different file extensions
const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff': 'application/font-woff',
    '.woff2': 'application/font-woff2',
    '.ttf': 'application/font-ttf',
    '.eot': 'application/vnd.ms-fontobject',
    '.otf': 'application/font-otf'
};

// Create HTTP server
const server = http.createServer((req, res) => {
    console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url}`);

    // Parse URL
    let filePath = '.' + req.url;
    if (filePath === './') {
        filePath = './frontend/login.html';
    } else if (!filePath.startsWith('./frontend/')) {
        filePath = './frontend' + req.url;
    }

    // Get file extension
    const extname = String(path.extname(filePath)).toLowerCase();
    const contentType = mimeTypes[extname] || 'application/octet-stream';

    // Read file
    fs.readFile(filePath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                // File not found
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end('<h1>404 - File Not Found</h1>', 'utf-8');
            } else {
                // Server error
                res.writeHead(500);
                res.end(`Server Error: ${error.code}`, 'utf-8');
            }
        } else {
            // Success - send file
            res.writeHead(200, { 
                'Content-Type': contentType,
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            });
            res.end(content, 'utf-8');
        }
    });
});

// Start server
server.listen(PORT, () => {
    const url = `http://localhost:${PORT}/login.html`;
    
    console.log('='.repeat(60));
    console.log('🚀 Digital Forensic System Server Started!');
    console.log('='.repeat(60));
    console.log(`📡 Server running at: ${url}`);
    console.log(`📁 Serving files from: ${FRONTEND_DIR}`);
    console.log('='.repeat(60));
    console.log('\n💡 Click the URL above or press Ctrl+C to stop the server\n');
    
    // Open browser automatically
    const platform = process.platform;
    let command;
    
    if (platform === 'win32') {
        command = `start ${url}`;
    } else if (platform === 'darwin') {
        command = `open ${url}`;
    } else {
        command = `xdg-open ${url}`;
    }
    
    exec(command, (error) => {
        if (error) {
            console.log('⚠️  Could not open browser automatically');
            console.log(`   Please manually open: ${url}`);
        } else {
            console.log('✅ Browser opened automatically');
        }
    });
    
    console.log('\n' + '='.repeat(60));
    console.log('Server is running... Press Ctrl+C to stop');
    console.log('='.repeat(60) + '\n');
});

// Handle server errors
server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.log(`❌ Error: Port ${PORT} is already in use!`);
        console.log(`   Please close the application using port ${PORT} or change PORT in server.js`);
    } else {
        console.log(`❌ Server error: ${error.message}`);
    }
    process.exit(1);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n🛑 Server stopped by user');
    server.close(() => {
        process.exit(0);
    });
});

