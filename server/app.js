const config = require('./rules/rules.json');  // Assuming rules.json is in utils/
const results = [];
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const whois = require('whois-json');
const { JSDOM } = require('jsdom');
const {
  checkTLD,
  checkKeywords,
  checkPatterns,
  checkSSL,
  checkDomainAge,
  checkExternalLinks
} = require('./utils/heuristics');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  const reasons = [];
  let progress = 0;
  let score = 100;

  let parsedURL;
  try {
    parsedURL = new URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
      },
      timeout: 7000
    });
    const htmlContent = response.data;
    const domain = parsedURL.hostname;

    // ✅ 1. TLD check
    const tldReason = checkTLD(url, config);
    if (tldReason) { reasons.push(tldReason); score -= 30; }
    progress = 20;

    // ✅ 2. Keyword check
    const keywordReasons = checkKeywords(htmlContent, config);
    if (keywordReasons.length > 0) {
      reasons.push(...keywordReasons);
      score -= keywordReasons.length * 10;
    }
    progress = 40;

    // ✅ 3. Pattern check
    const patternReasons = checkPatterns(url, config);
    if (patternReasons.length > 0) {
      reasons.push(...patternReasons);
      score -= patternReasons.length * 10;
    }
    progress = 60;

    // ✅ 4. SSL check (no config needed)
    const sslReason = checkSSL(parsedURL);
    if (sslReason) { reasons.push(sslReason); score -= 10; }
    progress = 70;

    // ✅ 5. Domain age check
    const whoisData = await whois(domain);
    const domainAgeReason = checkDomainAge(whoisData, config);
    if (domainAgeReason) { reasons.push(domainAgeReason); score -= 10; }
    progress = 85;

    // ✅ 6. External links
    const externalLinksReason = checkExternalLinks(htmlContent, url, config);
    if (externalLinksReason) { reasons.push(externalLinksReason); score -= 10; }
    progress = 100;

    const verdict = score < 70 ? 'suspicious' : 'safe';
    res.json({ verdict, progress, score, reasons });

  } catch (error) {
    console.error('Error fetching URL:', error.message);
    res.status(500).json({ error: 'Failed to fetch URL content' });
  }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));