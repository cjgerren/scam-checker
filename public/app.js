function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderList(items, emptyMessage = 'None detected.') {
  if (!Array.isArray(items) || items.length === 0) {
    return `<p>${escapeHtml(emptyMessage)}</p>`;
  }

  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

function getRiskClass(risk) {
  const value = String(risk || '').toLowerCase();
  if (value === 'high') return 'risk-high';
  if (value === 'medium') return 'risk-medium';
  return 'risk-low';
}

function getEls() {
  return {
    textInput: document.getElementById('textInput'),
    fileInput: document.getElementById('fileInput'),
    analyzeTextBtn: document.getElementById('analyzeTextBtn'),
    analyzeFileBtn: document.getElementById('analyzeFileBtn'),
    clearBtn: document.getElementById('clearBtn'),
    resultsDiv: document.getElementById('results'),
    statusDiv: document.getElementById('status'),
    regressionResultsDiv: document.getElementById('regression-results')
  };
}

function setStatus(message, isError = false) {
  const { statusDiv } = getEls();
  if (!statusDiv) return;
  statusDiv.textContent = message || '';
  statusDiv.className = isError ? 'status error' : 'status';
}

function clearResults() {
  const { resultsDiv } = getEls();
  if (resultsDiv) resultsDiv.innerHTML = '';
}

function renderError(message) {
  const { resultsDiv } = getEls();
  if (!resultsDiv) return;

  resultsDiv.innerHTML = `
    <div class="card">
      <h2>Something went wrong</h2>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
}

function renderRegressionResults(report) {
  const { regressionResultsDiv } = getEls();

  if (!regressionResultsDiv) {
    return;
  }

  if (!report || !Array.isArray(report.results)) {
    regressionResultsDiv.innerHTML = '';
    return;
  }

  regressionResultsDiv.innerHTML = report.results
    .map((test) => {
      const bubbleClass = test.pass ? 'pass' : 'fail';
      const statusText = test.pass ? 'PASS' : 'FAIL';
      const label = `${test.id || 'Unnamed Test'} - ${statusText}`;

      return `
        <div
          class="test-bubble ${bubbleClass}"
          title="${escapeHtml(label)}"
        >
          ${escapeHtml(label)}
        </div>
      `;
    })
    .join('');
}

async function loadRegressionResults() {
  try {
    const response = await fetch('/test-results');
    const report = await response.json();

    if (!response.ok) {
      throw new Error(report.error || 'Failed to load regression results.');
    }

    renderRegressionResults(report);
  } catch (error) {
    console.error('Failed to load regression results:', error);
    renderRegressionResults(null);
  }
}

function renderResult(data) {
  const { resultsDiv } = getEls();
  if (!resultsDiv) return;

  const risk = data.risk || 'Unknown';
  const riskClass = getRiskClass(risk);
  const riskScore = typeof data.riskScore === 'number' ? data.riskScore : 0;
  const scamType = data.scamType || 'Unknown';
  const summary = data.summary || 'No summary returned.';
  const sourceType = data.sourceType || 'unknown';
  const redFlags = Array.isArray(data.redFlags) ? data.redFlags : [];
  const nextSteps = Array.isArray(data.nextSteps) ? data.nextSteps : [];
  const urls = Array.isArray(data.urls) ? data.urls : [];
  const extractedText = data.extractedText || '';
  const emailMeta = data.emailMeta || null;
  const fileName = data.fileName || '';

  resultsDiv.innerHTML = `
    <div class="card">
      <h2>Verdict</h2>
      <div class="pill ${riskClass}">${escapeHtml(risk)} Risk</div>
      <p><strong>Risk Score:</strong> ${escapeHtml(riskScore)}</p>
      <p><strong>Scam Type:</strong> ${escapeHtml(scamType)}</p>
      <p><strong>Source Type:</strong> ${escapeHtml(sourceType)}</p>
      ${fileName ? `<p><strong>File Name:</strong> ${escapeHtml(fileName)}</p>` : ''}
      <p>${escapeHtml(summary)}</p>
    </div>

    <div class="card">
      <h3>🚩 Red Flags</h3>
      ${renderList(redFlags)}
    </div>

    <div class="card">
      <h3>✅ What To Do Next</h3>
      ${renderList(nextSteps)}
    </div>

    <div class="card">
      <h3>🔗 Links Found</h3>
      ${
        urls.length
          ? `<ul>${urls
              .map(
                (url) =>
                  `<li><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a></li>`
              )
              .join('')}</ul>`
          : '<p>No links found.</p>'
      }
    </div>

    ${
      emailMeta
        ? `
        <div class="card">
          <h3>📧 Email Details</h3>
          <p><strong>From:</strong> ${escapeHtml(emailMeta.from || 'Unknown')}</p>
          <p><strong>To:</strong> ${escapeHtml(emailMeta.to || 'Unknown')}</p>
          <p><strong>Subject:</strong> ${escapeHtml(emailMeta.subject || 'Unknown')}</p>
          <p><strong>Date:</strong> ${escapeHtml(emailMeta.date || 'Unknown')}</p>
        </div>
      `
        : ''
    }

    ${
      extractedText
        ? `
        <div class="card">
          <h3>📝 Extracted Text</h3>
          <pre>${escapeHtml(extractedText)}</pre>
        </div>
      `
        : ''
    }
  `;
}

async function analyzeText() {
  const { textInput } = getEls();
  const text = textInput ? textInput.value.trim() : '';

  if (!text) {
    renderError('Paste some text first.');
    setStatus('No pasted text to analyze.', true);
    return;
  }

  clearResults();
  setStatus('Analyzing pasted text...');

  try {
    const response = await fetch('/analyze-text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to analyze pasted text.');
    }

    renderResult(data);
    setStatus('Pasted text analyzed successfully.');
    await loadRegressionResults();
  } catch (error) {
    renderError(error.message || 'Unknown error.');
    setStatus(error.message || 'Unknown error.', true);
  }
}

async function analyzeFile() {
  const { fileInput } = getEls();
  const file = fileInput && fileInput.files ? fileInput.files[0] : null;

  if (!file) {
    renderError('Choose a file or screenshot first.');
    setStatus('No file selected.', true);
    return;
  }

  clearResults();
  setStatus(`Uploading and analyzing: ${file.name}`);

  try {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/analyze-file', {
      method: 'POST',
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to analyze uploaded file.');
    }

    renderResult(data);
    setStatus(`Finished analyzing: ${file.name}`);
    await loadRegressionResults();
  } catch (error) {
    renderError(error.message || 'Unknown error.');
    setStatus(error.message || 'Unknown error.', true);
  }
}

function clearAll() {
  const { textInput, fileInput, regressionResultsDiv } = getEls();

  if (textInput) textInput.value = '';
  if (fileInput) fileInput.value = '';

  clearResults();

  if (regressionResultsDiv) {
    regressionResultsDiv.innerHTML = '';
  }

  setStatus('');
}

window.addEventListener('load', () => {
  const els = getEls();

  console.log('Loaded button check:', {
    analyzeTextBtn: !!els.analyzeTextBtn,
    analyzeFileBtn: !!els.analyzeFileBtn,
    clearBtn: !!els.clearBtn,
    textInput: !!els.textInput,
    fileInput: !!els.fileInput,
    resultsDiv: !!els.resultsDiv,
    statusDiv: !!els.statusDiv,
    regressionResultsDiv: !!els.regressionResultsDiv,
    path: window.location.pathname
  });

  if (els.analyzeTextBtn) {
    els.analyzeTextBtn.addEventListener('click', analyzeText);
  }

  if (els.analyzeFileBtn) {
    els.analyzeFileBtn.addEventListener('click', analyzeFile);
  }

  if (els.clearBtn) {
    els.clearBtn.addEventListener('click', clearAll);
  }

  loadRegressionResults();
});