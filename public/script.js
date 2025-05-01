async function analyzeURL() {
  const url = document.getElementById('urlInput').value.trim();
  const resultEl = document.getElementById('result');
  const progressBar = document.getElementById('progressBar');

  if (!url) {
    resultEl.innerHTML = 'Please enter a URL.';
    return;
  }

  progressBar.style.width = '0%';
  resultEl.innerHTML = 'Checking...';

  try {
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok) {
      resultEl.innerHTML = `<span style="color:orange;">Error: ${data.error || 'Unexpected error'}</span>`;
      return;
    }

    const color = data.verdict === 'safe' ? 'green' : 'red';
    progressBar.style.width = '100%';
    progressBar.style.backgroundColor = color;

    resultEl.innerHTML = `
      <strong style="color:${color};">${data.verdict.toUpperCase()}</strong><br/>
      Score: ${data.score}<br/>
      Reasons:
      <ul>${data.reasons.map(r => `<li>${r}</li>`).join('')}</ul>
    `;
  } catch (error) {
    resultEl.innerHTML = `<span style="color:orange;">Error: ${error.message}</span>`;
  }
}
