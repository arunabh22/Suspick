const { JSDOM } = require('jsdom');

function checkTLD(url, config) {
  const domain = new URL(url).hostname;
  if (!config.validTLDs.some(tld => domain.endsWith(tld))) {
    return `Suspicious TLD found in domain: ${domain}`;
  }
  return null;
}

function checkKeywords(html, config) {
  const found = config.suspiciousKeywords.filter(keyword =>
    html.toLowerCase().includes(keyword.toLowerCase())
  );
  return found.map(k => `Keyword found: '${k}'`);
}

function checkPatterns(url, config) {
  return config.suspiciousPatterns
    .map(pattern => new RegExp(pattern, 'i'))
    .filter(regex => regex.test(url))
    .map(p => `Suspicious pattern matched: ${p}`);
}

function checkSSL(url) {
  const protocol = new URL(url).protocol;
  if (protocol !== 'https:') {
    return 'SSL not present: connection is not secure (HTTP)';
  }
  return null;
}

function checkDomainAge(whoisData, config) {
  const creationDate = new Date(
    whoisData.creationDate || whoisData.createdDate || whoisData.created
  );
  const ageInMonths = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24 * 30);
  if (isNaN(creationDate.getTime())) return null;
  if (ageInMonths < config.domainAgeThresholdMonths) {
    return `Domain age is less than ${config.domainAgeThresholdMonths} months (registered on ${creationDate.toISOString().split('T')[0]})`;
  }
  return null;
}

function checkExternalLinks(html, pageUrl, config) {
  const dom = new JSDOM(html);
  const anchors = [...dom.window.document.querySelectorAll('a[href]')];
  const domain = new URL(pageUrl).hostname;
  const externalLinks = anchors.filter(a => {
    try {
      const linkHost = new URL(a.href, pageUrl).hostname;
      return !linkHost.includes(domain);
    } catch {
      return false;
    }
  });
  if (externalLinks.length > config.externalLinkThreshold) {
    return `Page contains ${externalLinks.length} external links, which may indicate suspicious redirection behavior.`;
  }
  return null;
}

//whitelist website checker
function checkWhitelistedDomain(url, config) {
  const domain = new URL(url).hostname.replace(/^www\./, '');
  return config.whitelistDomains.includes(domain);
}

module.exports = {
  checkTLD,
  checkKeywords,
  checkPatterns,
  checkSSL,
  checkDomainAge,
  checkExternalLinks,
  checkWhitelistedDomain
};
