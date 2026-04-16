const fetch = require('node-fetch');

/**
 * Encrypts a string using the Bubble API endpoint
 */
async function encrypt(text) {
  if (!text) return text;

  const response = await fetch("https://upward.page/api/1.1/wf/encryption_encrypt_data", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.BUBBLE_AUTH_SECRET}`
    },
    body: JSON.stringify({ text: text })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Encryption API failed: ${response.status} - ${errText}`);
  }

  const data = await response.json();
  
  // Bubble usually nests workflow returns inside a "response" object,
  // but we also check the root level just in case it's flattened.
  return data.response?.encrypted || data.encrypted;
}

/**
 * Decrypts a string using the Bubble API endpoint
 */
async function decrypt(text) {
  if (!text) return text;

  const response = await fetch("https://upward.page/api/1.1/wf/encryption_decrypt_data", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.BUBBLE_AUTH_SECRET}`
    },
    body: JSON.stringify({ text: text })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Decryption API failed: ${response.status} - ${errText}`);
  }

  const data = await response.json();
  return data.response?.decrypted || data.decrypted;
}

module.exports = { encrypt, decrypt };
