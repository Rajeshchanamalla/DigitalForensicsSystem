/**
 * Email Notification Service
 * Uses Nodemailer
 */

const nodemailer = require('nodemailer');
const mysql = require('mysql2/promise');
const config = require('../config');

// Create connection pool
const pool = mysql.createPool(config.database);

// Email configuration (use environment variables in production)
const EMAIL_CONFIG = {
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: process.env.EMAIL_PORT || 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
};

// Create transporter (only if email is configured)
let transporter = null;
if (EMAIL_CONFIG.auth.user !== 'your-email@gmail.com') {
    transporter = nodemailer.createTransport(EMAIL_CONFIG);
}

/**
 * Send email notification
 */
async function sendEmail(to, subject, html, text = null) {
    if (!transporter) {
        console.warn('Email not configured. Skipping email send.');
        // Store in database for later sending
        await storeEmailNotification(to, 'email', subject, html || text);
        return { sent: false, message: 'Email not configured' };
    }

    try {
        const mailOptions = {
            from: `"Digital Forensic System" <${EMAIL_CONFIG.auth.user}>`,
            to: to,
            subject: subject,
            html: html,
            text: text || html.replace(/<[^>]*>/g, '') // Strip HTML for text version
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.messageId);
        
        // Store in database
        await storeEmailNotification(to, 'email', subject, html || text, true);
        
        return { sent: true, messageId: info.messageId };
    } catch (error) {
        console.error('Email send error:', error);
        // Store in database as failed
        await storeEmailNotification(to, 'email', subject, html || text, false);
        return { sent: false, error: error.message };
    }
}

/**
 * Store email notification in database
 */
async function storeEmailNotification(userId, type, subject, message, sent = false) {
    try {
        await pool.execute(
            `INSERT INTO email_notifications (user_id, type, subject, message, sent, sent_at) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, type, subject, message, sent ? 1 : 0, sent ? new Date() : null]
        );
    } catch (error) {
        console.error('Error storing email notification:', error);
    }
}

/**
 * Send evidence uploaded notification
 */
async function notifyEvidenceUploaded(userId, caseId, fileName) {
    const subject = `New Evidence Uploaded - Case ${caseId}`;
    const html = `
        <h2>New Evidence Uploaded</h2>
        <p>A new evidence file has been uploaded to the system.</p>
        <ul>
            <li><strong>Case ID:</strong> ${caseId}</li>
            <li><strong>File Name:</strong> ${fileName}</li>
            <li><strong>Uploaded At:</strong> ${new Date().toLocaleString()}</li>
        </ul>
        <p>Please log in to the system to view and verify the evidence.</p>
    `;
    
    return await sendEmail(userId, subject, html);
}

/**
 * Send evidence verified notification
 */
async function notifyEvidenceVerified(userId, caseId, fileName, isValid) {
    const subject = `Evidence Verified - Case ${caseId}`;
    const status = isValid ? 'VERIFIED' : 'FAILED';
    const html = `
        <h2>Evidence Verification ${status}</h2>
        <p>The evidence file has been ${isValid ? 'successfully verified' : 'failed verification'}.</p>
        <ul>
            <li><strong>Case ID:</strong> ${caseId}</li>
            <li><strong>File Name:</strong> ${fileName}</li>
            <li><strong>Status:</strong> ${status}</li>
            <li><strong>Verified At:</strong> ${new Date().toLocaleString()}</li>
        </ul>
    `;
    
    return await sendEmail(userId, subject, html);
}

/**
 * Send status change notification
 */
async function notifyStatusChange(userId, caseId, fileName, oldStatus, newStatus) {
    const subject = `Evidence Status Changed - Case ${caseId}`;
    const html = `
        <h2>Evidence Status Updated</h2>
        <p>The status of an evidence file has been changed.</p>
        <ul>
            <li><strong>Case ID:</strong> ${caseId}</li>
            <li><strong>File Name:</strong> ${fileName}</li>
            <li><strong>Previous Status:</strong> ${oldStatus}</li>
            <li><strong>New Status:</strong> ${newStatus}</li>
            <li><strong>Changed At:</strong> ${new Date().toLocaleString()}</li>
        </ul>
    `;
    
    return await sendEmail(userId, subject, html);
}

module.exports = {
    sendEmail,
    notifyEvidenceUploaded,
    notifyEvidenceVerified,
    notifyStatusChange,
    storeEmailNotification
};

