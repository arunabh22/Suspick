const { detectMaliciousAnchorText, analyzeDOM } = require('./utils/dom');
const { checkTLD, checkKeywords, checkPatterns, checkSSL, checkDomainAge, checkExternalLinks } = require('./utils/heuristics');
const { checkSafeBrowsing } = require('./utils/safeBrowsing');
const config = require('./rules/rules.json');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const whois = require('whois-json');
const { JSDOM } = require('jsdom');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.post('/analyze', async (req, res) => {
  const deep = req.query.deep === 'true';
  const { url } = req.body;
  const reasons = [];
  let progress = 0;
  let score = 100;

  // Validate URL
  let parsedURL;
  try {
    parsedURL = new URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Run Safe Browsing *first* if deep scan is enabled
  let verdict = 'safe';
  if (deep) {
    const threatData = await checkSafeBrowsing(url);
    console.log('Safe Browsing API returned:', JSON.stringify(threatData, null, 2));

    if (threatData?.matches) {
      const threatType = threatData.matches[0]?.threatType || 'Unknown Threat';
      reasons.unshift(`🚨 Flagged by Google Safe Browsing API (${threatType})`);
      return res.json({ verdict: 'suspicious', progress: 100, score: 0, reasons });
    }
  }

  try {
    const response = await axios.get(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 7000
    });
    const htmlContent = response.data;
    const domain = parsedURL.hostname;

    // 1. TLD
    const tldReason = checkTLD(url, config);
    if (tldReason) { reasons.push(tldReason); score -= 30; }
    progress = 15;

    // 2. Keywords
    const keywordReasons = checkKeywords(htmlContent, config);
    if (keywordReasons.length) { reasons.push(...keywordReasons); score -= keywordReasons.length * 10; }
    progress = 30;

    // 3. URL Patterns
    const patternReasons = checkPatterns(url, config);
    if (patternReasons.length) { reasons.push(...patternReasons); score -= patternReasons.length * 10; }
    progress = 45;

    // 4. SSL
    const sslReason = checkSSL(parsedURL);
    if (sslReason) { reasons.push(sslReason); score -= 10; }
    progress = 55;

    // 5. Domain Age
    const whoisData = await whois(domain);
    const domainAgeReason = checkDomainAge(whoisData, config);
    if (domainAgeReason) { reasons.push(domainAgeReason); score -= 10; }
    progress = 70;

    // 6. External Links
    const externalLinksReason = checkExternalLinks(htmlContent, url, config);
    if (externalLinksReason) { reasons.push(externalLinksReason); score -= 10; }
    progress = 85;

    // 7. DOM Analysis
    const { reasons: domReasons, scorePenalty } = analyzeDOM(htmlContent, url);
    if (domReasons.length) { reasons.push(...domReasons); score -= scorePenalty; }

    // 8. Malicious Anchor Text
    const dom = new JSDOM(htmlContent, { url });
    const anchorTextReasons = detectMaliciousAnchorText(dom);
    if (anchorTextReasons.length) { reasons.push(...anchorTextReasons); score -= anchorTextReasons.length * 10; }

    verdict = score < 70 ? 'suspicious' : 'safe';
    return res.json({ verdict, progress: 100, score, reasons });

  } catch (error) {
    console.error('Error fetching URL:', error.message);

    // If deep mode, Safe Browsing already ran — we still return that result
    if (deep && reasons.length) {
      return res.json({ verdict: 'suspicious', progress: 100, score: 0, reasons });
    }

    return res.status(500).json({ error: 'Failed to fetch URL content' });
  }
});


app.listen(3000, () => console.log('Server running on http://localhost:3000'));