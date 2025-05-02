const { JSDOM } = require('jsdom');

function analyzeDOM(html, pageUrl) {
  const reasons = [];
  let scorePenalty = 0;
  const dom = new JSDOM(html);
  const document = dom.window.document;
  const pageDomain = new URL(pageUrl).hostname;

  // 1. Form Action Check
  const forms = [...document.querySelectorAll('form')];
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action) {
      try {
        const actionUrl = new URL(action, pageUrl);
        if (!actionUrl.hostname.includes(pageDomain)) {
          reasons.push(`Form posts to a different domain: ${actionUrl.hostname}`);
          scorePenalty += 20;
        }
        if (actionUrl.protocol !== 'https:') {
          reasons.push(`Form posts over insecure connection: ${actionUrl.href}`);
          scorePenalty += 10;
        }
      } catch (e) {}
    }
  });

  // 2. Hidden Inputs Check
  const hiddenInputs = [...document.querySelectorAll('input[type="hidden"]')];
  if (hiddenInputs.length > 5) {
    reasons.push(`Page has ${hiddenInputs.length} hidden inputs, possibly suspicious.`);
    scorePenalty += 10;
  }

  // 3. Meta Refresh Redirect Check
  const meta = document.querySelector('meta[http-equiv="refresh"]');
  if (meta) {
    const content = meta.getAttribute('content');
    const match = content && content.match(/\d+;\s*url=(.*)/i);
    if (match) {
      const redirectUrl = match[1];
      try {
        const target = new URL(redirectUrl, pageUrl);
        if (!target.hostname.includes(pageDomain)) {
          reasons.push(`Meta refresh redirects to another domain: ${target.href}`);
          scorePenalty += 10;
        }
      } catch (e) {}
    }
  }

  // 4. Iframe Check
  const iframes = [...document.querySelectorAll('iframe')];
  iframes.forEach(iframe => {
    const src = iframe.getAttribute('src');
    if (src) {
      try {
        const iframeUrl = new URL(src, pageUrl);
        if (!iframeUrl.hostname.includes(pageDomain)) {
          reasons.push(`Iframe embeds content from external domain: ${iframeUrl.hostname}`);
          scorePenalty += 10;
        }
      } catch (e) {}
    }
  });
  if (iframes.length > 0 && document.body.children.length === 1 && document.body.firstElementChild.tagName === 'IFRAME') {
    reasons.push('Page is a full-screen iframe, which is often used in phishing.');
    scorePenalty += 20;
  }

  // 5. Suspicious Style Checks
  const elements = [...document.querySelectorAll('*')];
  let hiddenOverlay = false;
  elements.forEach(el => {
    const style = el.getAttribute('style') || '';
    if (style.match(/opacity\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden/i)) {
      hiddenOverlay = true;
    }
  });
  if (hiddenOverlay) {
    reasons.push('Page contains hidden or invisible elements which may be used for clickjacking.');
    scorePenalty += 10;
  }

  // 6. Obfuscated Script Check
  const scripts = [...document.querySelectorAll('script')];
  scripts.forEach(script => {
    const content = script.textContent || '';
    if (content.match(/eval\(|atob\(|Function\(|setTimeout\(/)) {
      reasons.push('Page uses obfuscated or dynamic script functions like eval or atob.');
      scorePenalty += 15;
    }
  });

  return { reasons, scorePenalty };
}

function detectMaliciousAnchorText(dom) {
    const baitPhrases = ['download malware', 'get free antivirus', 'security patch', 'system update'];
    const anchors = [...dom.window.document.querySelectorAll('a')];
  
    const flagged = anchors.filter(a =>
      baitPhrases.some(p => a.textContent.toLowerCase().includes(p))
    );
  
    return flagged.length > 0 ? ['Page contains anchor text with suspicious download or bait phrases.'] : [];
  }
  
  module.exports = {
    detectMaliciousAnchorText
  };
  

module.exports = { analyzeDOM , detectMaliciousAnchorText };