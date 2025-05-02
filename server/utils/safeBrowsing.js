require('dotenv').config();  // Load .env before anything else
const axios = require('axios');

// Safely read API key from environment
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
if (!GOOGLE_API_KEY) {
  console.warn('Warning: GOOGLE_API_KEY is not set. Safe Browsing checks will be disabled.');
}

/**
 * Queries Google Safe Browsing API v4 for threat matches.
 * @param {string} url - The URL to check.
 * @returns {Promise<object|null>} - The API response object or null on error.
 */
async function checkSafeBrowsing(url) {
  if (!GOOGLE_API_KEY) return null;
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
    if (err.response && err.response.data) {
      console.error("Safe Browsing API response data:", JSON.stringify(err.response.data, null, 2));
    }
    return null;
  }
}

module.exports = {
  checkSafeBrowsing
};
