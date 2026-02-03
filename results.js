let allResults = [];

// Get results from URL parameters
const urlParams = new URLSearchParams(window.location.search);
const resultsData = urlParams.get('data');

if (resultsData) {
  try {
    allResults = JSON.parse(decodeURIComponent(resultsData));
    displayResults(allResults);
  } catch (e) {
    document.getElementById('loading').innerHTML = '<p style="color: var(--error);">Error loading results</p>';
  }
}

function displayResults(results) {
  const loadingDiv = document.getElementById('loading');
  const resultsDiv = document.getElementById('results');
  const bulkActions = document.getElementById('bulkActions');
  const statsText = document.getElementById('stats-text');
  const chartPlaceholder = document.getElementById('chart-placeholder');

  loadingDiv.style.display = 'none';
  bulkActions.style.display = 'flex';

  // Calculate stats
  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;
  const maliciousResults = results.filter(r => r.success && r.data.last_analysis_stats.malicious > 0);
  const maliciousCount = maliciousResults.length;
  const cleanCount = successful - maliciousCount;

  // Update Stats Text
  statsText.innerHTML = `
    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
      <span style="color: var(--text-secondary);">Total Analyzed</span>
      <strong>${results.length}</strong>
    </div>
    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
      <span style="color: var(--text-secondary);">Malicious</span>
      <strong style="color: var(--error);">${maliciousCount}</strong>
    </div>
    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
      <span style="color: var(--text-secondary);">Clean/Undetected</span>
      <strong style="color: var(--success);">${cleanCount}</strong>
    </div>
    <div style="display: flex; justify-content: space-between;">
      <span style="color: var(--text-secondary);">Errors</span>
      <strong style="color: var(--warning);">${failed}</strong>
    </div>
  `;

  // Render Chart
  const total = results.length || 1; // avoid divide by zero
  const pMalicious = (maliciousCount / total) * 100;
  const pClean = (cleanCount / total) * 100;
  // The rest is failed
  
  // We need cumulative percentages for conic-gradient
  // malicious: 0% -> pMalicious%
  // clean: pMalicious% -> (pMalicious + pClean)%
  // failed: remainder
  
  const endMalicious = pMalicious;
  const endClean = pMalicious + pClean;

  chartPlaceholder.innerHTML = `
    <div class="chart-donut" style="--p-malicious: ${endMalicious}%; --p-clean: ${endClean}%;">
      <div class="chart-text">
        <span class="chart-number">${maliciousCount}</span>
        <span class="chart-label">THREATS</span>
      </div>
    </div>
  `;

  // Display each result
  results.forEach((result, index) => {
    if (result.success) {
      resultsDiv.appendChild(createResultCard(result.data, index));
    } else {
      resultsDiv.appendChild(createErrorCard(result.hash, result.error, index));
    }
  });

  // Setup bulk actions
  setupBulkActions(results);
}

function createResultCard(data, index) {
  const card = document.createElement('div');
  card.className = 'card animate-fade-in';
  card.style.animationDelay = `${index * 50}ms`;
  
  const isMalicious = data.last_analysis_stats.malicious > 0;
  const badgeClass = isMalicious ? 'badge-malicious' : 'badge-clean';
  const badgeText = isMalicious ? 'MALICIOUS' : 'CLEAN';
  const fileName = data.meaningful_name || 'Unknown File';
  const score = `${data.last_analysis_stats.malicious}/${data.last_analysis_stats.malicious + data.last_analysis_stats.undetected}`;
  
  card.innerHTML = `
    <div class="flex-between" style="margin-bottom: 16px;">
      <div>
        <div style="font-weight: 600; font-size: 15px; margin-bottom: 4px; word-break: break-all;">${fileName}</div>
        <div style="font-size: 12px; color: var(--text-secondary);">${formatBytes(data.size)} • ${data.type_description || 'Unknown'}</div>
      </div>
      <div class="badge ${badgeClass}">${badgeText} ${score}</div>
    </div>
    
    <div class="hash-row">
      <span class="hash-text">MD5: ${data.md5}</span>
      <button class="copy-btn" data-hash="${data.md5}">COPY</button>
    </div>
    
    <div class="hash-row">
      <span class="hash-text">SHA1: ${data.sha1}</span>
      <button class="copy-btn" data-hash="${data.sha1}">COPY</button>
    </div>
    
    <div class="hash-row">
      <span class="hash-text">SHA256: ${data.sha256}</span>
      <button class="copy-btn" data-hash="${data.sha256}">COPY</button>
    </div>
    
    <div style="margin-top: 16px; text-align: right;">
      <a href="https://www.virustotal.com/gui/file/${data.sha256}" target="_blank" style="font-size: 12px; color: var(--accent-primary); text-decoration: none; font-weight: 600;">
        VIEW FULL REPORT &rarr;
      </a>
    </div>
  `;
  
  // Setup copy buttons
  card.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const hash = btn.getAttribute('data-hash');
      copyToClipboard(hash, btn);
    });
  });
  
  return card;
}

function createErrorCard(hash, error, index) {
  const card = document.createElement('div');
  card.className = 'card animate-fade-in';
  card.style.borderColor = 'var(--error)';
  
  card.innerHTML = `
    <div style="color: var(--error); font-weight: 600; margin-bottom: 8px;">
      ❌ Failed to fetch: ${hash}
    </div>
    <div style="font-size: 12px; color: var(--text-secondary);">${error}</div>
  `;
  
  return card;
}

function copyToClipboard(text, button) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.textContent;
    button.textContent = 'COPIED';
    button.style.color = 'var(--success)';
    
    setTimeout(() => {
      button.textContent = originalText;
      button.style.color = '';
    }, 2000);
  });
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function setupBulkActions(results) {
  const successfulResults = results.filter(r => r.success).map(r => r.data);
  
  // JSON Download
  const btnJson = document.getElementById('downloadJson');
  if (btnJson) {
      btnJson.addEventListener('click', () => {
        const json = JSON.stringify(successfulResults, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        downloadBlob(blob, `virustotal-results-${Date.now()}.json`);
      });
  }
  
  // CSV Download
  const btnCsv = document.getElementById('downloadCsv');
  if (btnCsv) {
      btnCsv.addEventListener('click', () => {
        const headers = ['File Name', 'MD5', 'SHA1', 'SHA256', 'Malicious', 'Undetected', 'Link'];
        const csvContent = [
            headers.join(','),
            ...successfulResults.map(r => {
                const row = [
                    `"${r.meaningful_name || ''}"`,
                    r.md5,
                    r.sha1,
                    r.sha256,
                    r.last_analysis_stats.malicious,
                    r.last_analysis_stats.undetected,
                    `"https://www.virustotal.com/gui/file/${r.sha256}"`
                ];
                return row.join(',');
            })
        ].join('\n');
        
        const blob = new Blob([csvContent], { type: 'text/csv' });
        downloadBlob(blob, `virustotal-results-${Date.now()}.csv`);
      });
  }
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
