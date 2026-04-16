const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
// GCM standard IV length is 12 bytes
const IV_LENGTH = 12; 

/**
 * Safely derives a 32-byte key from the environment variable.
 * AES-256 requires exactly 32 bytes. Using a SHA-256 hash ensures 
 * the key is always the correct length regardless of the env string.
 */
function getKey() {
  const secret = process.env.AES_ENCRYPTION_KEY;
  if (!secret) {
    throw new Error("AES_ENCRYPTION_KEY environment variable is missing.");
  }
  return crypto.createHash('sha256').update(String(secret)).digest();
}

/**
 * Encrypts a string using AES-256-GCM.
 * Returns a colon-separated string: "iv:authTag:encryptedData"
 */
function encrypt(text) {
  if (!text) return text;

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts a previously encrypted string.
 */
function decrypt(encryptedString) {
  if (!encryptedString) return encryptedString;

  const parts = encryptedString.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted text format. Expected iv:authTag:ciphertext');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encryptedText = parts[2];

  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

module.exports = { encrypt, decrypt };