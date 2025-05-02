// utils/safeBrowsing.js
const axios = require('axios');
// utils/safeBrowsing.js
require('dotenv').config();            // ← Load .env first
//const axios = require('axios');

//const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;


// Replace with your actual Google Safe Browsing API key
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;

/**
 * Queries Google Safe Browsing API v4 for threat matches.
 * @param {string} url - The URL to check.
 * @returns {Promise<object|null>} - The API response object or null on error.
 */
async function checkSafeBrowsing(url) {
  try {
    const requestBody = {
      client: {
        clientId: "suspicious-url-analyzer",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      requestBody
    );

    return response.data;
  } catch (err) {
    console.error("Safe Browsing API error:", err.message);
    return null;
  }
}

module.exports = {
  checkSafeBrowsing
};