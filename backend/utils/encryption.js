/**
 * File Encryption Utilities
 * Uses AES-256-CBC encryption
 */

const crypto = require('crypto');
const CryptoJS = require('crypto-js');

const ALGORITHM = 'aes-256-cbc';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits

/**
 * Generate encryption key
 */
function generateEncryptionKey() {
    return crypto.randomBytes(KEY_LENGTH).toString('hex');
}

/**
 * Encrypt file buffer
 */
function encryptFile(buffer, key) {
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key, 'hex'), iv);
        
        const encrypted = Buffer.concat([
            cipher.update(buffer),
            cipher.final()
        ]);

        return {
            encryptedData: encrypted,
            iv: iv.toString('hex')
        };
    } catch (error) {
        throw new Error(`Encryption failed: ${error.message}`);
    }
}

/**
 * Decrypt file buffer
 */
function decryptFile(encryptedBuffer, key, ivHex) {
    try {
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(key, 'hex'), iv);
        
        const decrypted = Buffer.concat([
            decipher.update(encryptedBuffer),
            decipher.final()
        ]);

        return decrypted;
    } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

/**
 * Hash encryption key (for storage)
 */
function hashEncryptionKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Encrypt text data
 */
function encryptText(text, key) {
    return CryptoJS.AES.encrypt(text, key).toString();
}

/**
 * Decrypt text data
 */
function decryptText(encryptedText, key) {
    const bytes = CryptoJS.AES.decrypt(encryptedText, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

module.exports = {
    generateEncryptionKey,
    encryptFile,
    decryptFile,
    hashEncryptionKey,
    encryptText,
    decryptText,
    ALGORITHM
};

