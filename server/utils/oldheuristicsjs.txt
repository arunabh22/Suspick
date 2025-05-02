const fs = require('fs');
const path = require('path');

// Load heuristic rules once from rules.json
const rulesPath = path.join(__dirname, '..', 'rules', 'rules.json');
const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));

/**
 * Check if the URL's TLD is in the suspicious list
 */
function checkTLD(url) {
  try {
    const { hostname } = new URL(url);
    const tld = hostname.substring(hostname.lastIndexOf('.'));
    if (rules.badTLDs.includes(tld)) {
      return `Suspicious TLD: ${tld}`;
    }
  } catch (err) {
    return null;
  }
  return null;
}

/**
 * Check if any fraud-related keyword exists in the page content
 */
function checkKeywords(content) {
  const matches = [];
  for (const keyword of rules.keywords) {
    const regex = new RegExp(`\\b${keyword}\\b`, 'i');
    if (regex.test(content)) {
      matches.push(`Keyword found: '${keyword}'`);
    }
  }
  return matches;
}

/**
 * Check if the URL matches any suspicious pattern
 */
function checkPatterns(url) {
  const matches = [];
  for (const pattern of rules.urlPatterns) {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(url)) {
      matches.push(`Pattern match: ${pattern}`);
    }
  }
  return matches;
}

module.exports = {
  checkTLD,
  checkKeywords,
  checkPatterns
};