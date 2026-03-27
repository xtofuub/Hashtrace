let allResults = [];

// Read results from chrome.storage.local.
// We no longer pass data via URL params — encodeURIComponent on large enriched
// relation payloads (50-150KB) silently corrupts the JSON, causing blank pages.
const urlParams = new URLSearchParams(window.location.search);
const storageKey = urlParams.get('key');

if (storageKey) {
  chrome.storage.local.get(storageKey, (stored) => {
    const payload = stored[storageKey];
    if (payload && payload.results) {
      allResults = payload.results;
      chrome.storage.local.remove(storageKey); // clean up after reading
      displayResults(allResults);
    } else {
      document.getElementById('loading').innerHTML =
        '<p style="color: var(--error);">Results not found in storage. Please try again.</p>';
    }
  });
} else {
  // Fallback: legacy ?data= URL param (for old bookmarked result pages)
  const resultsData = urlParams.get('data');
  if (resultsData) {
    try {
      allResults = JSON.parse(decodeURIComponent(resultsData));
      displayResults(allResults);
    } catch (e) {
      document.getElementById('loading').innerHTML =
        '<p style="color: var(--error);">Error parsing results data.</p>';
    }
  } else {
    document.getElementById('loading').innerHTML =
      '<p style="color: var(--text-secondary);">No results to display.</p>';
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

  // Deduplicate successful results by sha256 (fallback to md5)
  const uniqueMap = new Map();
  const uniqueResults = [];
  let duplicatesFilesCount = 0;
  const failedResults = [];

  results.forEach(r => {
    if (r.success && r.data) {
      const key = (r.data.sha256 || r.data.md5 || '').toLowerCase();
      if (key && !uniqueMap.has(key)) {
        uniqueMap.set(key, r);
        uniqueResults.push(r);
      } else {
        duplicatesFilesCount++;
      }
    } else {
      failedResults.push(r);
    }
  });

  const successful = uniqueResults.length;
  const failed = failedResults.length;
  const maliciousResults = uniqueResults.filter(r => r.data.last_analysis_stats.malicious > 0);
  const maliciousCount = maliciousResults.length;
  const cleanCount = successful - maliciousCount;

  statsText.innerHTML = `
    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
      <span style="color: var(--text-secondary);">Total Analyzed</span>
      <strong>${uniqueResults.length + failedResults.length}</strong>
    </div>
    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
      <span style="color: var(--text-secondary);">Same-File Duplicates</span>
      <strong>${duplicatesFilesCount}</strong>
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

  const total = results.length || 1;
  const pMalicious = (maliciousCount / total) * 100;
  const pClean = (cleanCount / total) * 100;
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

  uniqueResults.forEach((result, index) => {
    resultsDiv.appendChild(createResultCard(result.data, index));
  });
  failedResults.forEach((result, index) => {
    resultsDiv.appendChild(createErrorCard(result.hash, result.error, uniqueResults.length + index));
  });

  setupBulkActions(uniqueResults);
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

  // Build relations HTML safely as a separate step — never inline complex logic
  // inside a template literal assigned to innerHTML, as any thrown error makes
  // the entire card go blank with no visible error.
  const relationsHtml = buildRelationsHtml(data.relations, isMalicious);

  card.innerHTML = `
    <div class="flex-between" style="margin-bottom: 16px;">
      <div>
        <div style="font-weight: 600; font-size: 15px; margin-bottom: 4px; word-break: break-all;">${fileName}</div>
        <div style="font-size: 12px; color: var(--text-secondary);">${formatBytes(data.size)} • ${data.type_description || 'Unknown'}</div>
      </div>
      <div class="badge ${badgeClass}">${badgeText} ${score}</div>
    </div>

    <div class="hash-row">
      <span class="hash-text clickable" data-hash="${data.md5}" title="Click to copy">MD5: ${data.md5}</span>
      <button class="copy-btn" data-hash="${data.md5}">COPY</button>
    </div>

    <div class="hash-row">
      <span class="hash-text clickable" data-hash="${data.sha1}" title="Click to copy">SHA1: ${data.sha1}</span>
      <button class="copy-btn" data-hash="${data.sha1}">COPY</button>
    </div>

    <div class="hash-row">
      <span class="hash-text clickable" data-hash="${data.sha256}" title="Click to copy">SHA256: ${data.sha256}</span>
      <button class="copy-btn" data-hash="${data.sha256}">COPY</button>
    </div>

    ${relationsHtml}

    <div style="margin-top: 16px; text-align: right;">
      <a href="https://www.virustotal.com/gui/file/${data.sha256}" target="_blank"
         style="font-size: 12px; color: var(--accent-primary); text-decoration: none; font-weight: 600;">
        VIEW FULL REPORT &rarr;
      </a>
    </div>
  `;

  card.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => copyToClipboard(btn.getAttribute('data-hash'), btn));
  });
  card.querySelectorAll('.hash-text.clickable').forEach(span => {
    span.addEventListener('click', () => copyToClipboard(span.getAttribute('data-hash'), span));
  });

  return card;
}

// Build the entire relations section as a plain string.
// Kept as a separate function so any error here doesn't blank the whole card.
function buildRelationsHtml(rel, isMalicious) {
  try {
    if (!rel) return '';

    const allParents = [...(rel.parents || []), ...(rel.overlay_parents || []), ...(rel.email_parents || [])];
    const allChildren = [...(rel.bundles || []), ...(rel.dropped || []), ...(rel.pe_children || [])];
    const hasContacted = (rel.ips?.length || rel.domains?.length || rel.contacted_urls?.length);
    const hasEmbedded = (rel.embedded_domains?.length || rel.embedded_ips?.length || rel.embedded_urls?.length);
    const hasItw = rel.itw_urls?.length;

    const hasAny = allParents.length || allChildren.length || hasContacted || hasEmbedded || hasItw;
    if (!isMalicious && !hasAny) return '';

    const accentColor = isMalicious ? 'var(--error)' : 'var(--text-secondary)';
    const borderColor = isMalicious ? 'rgba(255,23,68,0.15)' : 'rgba(255,255,255,0.06)';

    const sections = [];

    // --- Helper: render file objects (parents / children) ---
    function fileList(items, icon, limit) {
      limit = limit || 4;
      if (!items || items.length === 0) return '';
      let html = items.slice(0, limit).map(function (f) {
        const name = (f.attributes && f.attributes.meaningful_name) ? f.attributes.meaningful_name : null;
        const stats = f.attributes && f.attributes.last_analysis_stats;
        const scoreHtml = stats
          ? '<span style="color:' + (stats.malicious > 0 ? 'var(--error)' : 'var(--success)') + ';font-weight:700;">' + stats.malicious + '/' + (stats.malicious + stats.undetected) + '</span>'
          : '<span style="opacity:0.4;">no score</span>';
        const displayName = name || (f.id.substring(0, 22) + '…');
        const shortId = f.id.substring(0, 20) + '…';
        return '<div style="font-size:11px;display:flex;align-items:start;gap:6px;padding:3px 0;">'
          + '<span style="opacity:0.45;margin-top:1px;">' + icon + '</span>'
          + '<div style="flex:1;min-width:0;">'
          + '<div style="font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="' + (name || f.id) + '">' + displayName + '</div>'
          + '<div style="font-size:10px;opacity:0.55;font-family:var(--font-mono);">' + shortId + ' · ' + scoreHtml + '</div>'
          + '</div></div>';
      }).join('');
      if (items.length > limit) {
        html += '<div style="font-size:10px;color:var(--text-secondary);padding-left:18px;margin-top:2px;">+' + (items.length - limit) + ' more</div>';
      }
      return html;
    }

    // --- Helper: render infrastructure chips (IPs / domains / URLs) ---
    function infraList(items, limit) {
      limit = limit || 6;
      if (!items || items.length === 0) return '';
      let html = items.slice(0, limit).map(function (i) {
        return '<span style="display:inline-block;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:4px;padding:1px 6px;font-size:10px;color:var(--text-secondary);font-family:var(--font-mono);word-break:break-all;margin:1px 2px;">' + i.id + '</span>';
      }).join('');
      if (items.length > limit) {
        html += '<span style="font-size:10px;color:var(--text-secondary);"> +' + (items.length - limit) + ' more</span>';
      }
      return html;
    }

    function sectionHeader(emoji, label, count) {
      return '<div style="font-size:10px;color:var(--text-secondary);font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">'
        + emoji + ' ' + label + ' (' + count + ')</div>';
    }

    // 1. Parent files
    if (allParents.length > 0) {
      sections.push(
        '<div>' + sectionHeader('📦', 'Execution / Container Parents', allParents.length)
        + fileList(allParents, '↑', 4) + '</div>'
      );
    }

    // 2. Child files
    if (allChildren.length > 0) {
      sections.push(
        '<div>' + sectionHeader('📄', 'Contained / Dropped Files', allChildren.length)
        + fileList(allChildren, '↓', 4) + '</div>'
      );
    }

    // 3. Contacted infrastructure (runtime)
    if (hasContacted) {
      const total = (rel.ips?.length || 0) + (rel.domains?.length || 0) + (rel.contacted_urls?.length || 0);
      let inner = '';
      if (rel.ips?.length) inner += '<div style="margin-bottom:4px;">' + infraList(rel.ips, 6) + '</div>';
      if (rel.domains?.length) inner += '<div style="margin-bottom:4px;">' + infraList(rel.domains, 6) + '</div>';
      if (rel.contacted_urls?.length) inner += '<div>' + infraList(rel.contacted_urls, 3) + '</div>';
      sections.push('<div>' + sectionHeader('🌐', 'Contacted at Runtime', total) + inner + '</div>');
    }

    // 4. Embedded strings (static)
    if (hasEmbedded) {
      const total = (rel.embedded_ips?.length || 0) + (rel.embedded_domains?.length || 0) + (rel.embedded_urls?.length || 0);
      let inner = '';
      if (rel.embedded_ips?.length) inner += '<div style="margin-bottom:4px;">' + infraList(rel.embedded_ips, 6) + '</div>';
      if (rel.embedded_domains?.length) inner += '<div style="margin-bottom:4px;">' + infraList(rel.embedded_domains, 6) + '</div>';
      if (rel.embedded_urls?.length) inner += '<div>' + infraList(rel.embedded_urls, 3) + '</div>';
      sections.push('<div>' + sectionHeader('🔍', 'Embedded Strings (Static)', total) + inner + '</div>');
    }

    // 5. In-the-wild distribution URLs
    if (hasItw) {
      sections.push(
        '<div>' + sectionHeader('📡', 'In-the-Wild Download URLs', rel.itw_urls.length)
        + infraList(rel.itw_urls, 3) + '</div>'
      );
    }

    // Malicious but no relations found
    if (sections.length === 0 && isMalicious) {
      sections.push('<div style="font-size:11px;color:var(--text-secondary);font-style:italic;opacity:0.7;">No associated relations found in VirusTotal for this sample.</div>');
    }

    if (sections.length === 0) return '';

    return '<div style="margin-top:12px;padding:12px;background:rgba(255,23,68,0.03);border-radius:var(--radius-sm);border:1px solid ' + borderColor + ';border-left:3px solid ' + accentColor + ';">'
      + '<div style="font-size:11px;font-weight:700;color:' + accentColor + ';margin-bottom:10px;text-transform:uppercase;letter-spacing:0.5px;display:flex;justify-content:space-between;">'
      + '<span>VirusTotal Relations</span><span style="opacity:0.5;font-weight:400;">Analysis Context</span></div>'
      + '<div style="display:flex;flex-direction:column;gap:10px;">'
      + sections.join('')
      + '</div></div>';

  } catch (e) {
    console.error('buildRelationsHtml error:', e);
    return ''; // never blank the card due to a relations rendering error
  }
}

function createErrorCard(hash, error, index) {
  const card = document.createElement('div');
  card.className = 'card animate-fade-in';
  card.style.borderColor = 'var(--error)';

  card.innerHTML = `
    <div class="hash-row" style="border: 1px solid rgba(255, 23, 68, 0.3);">
      <span class="hash-text clickable" data-hash="${hash}" style="color: var(--error);" title="Click to copy">❌ Failed to fetch: ${hash}</span>
    </div>
    <div style="font-size: 12px; color: var(--text-secondary);">${error}</div>
  `;

  const span = card.querySelector('.hash-text.clickable');
  if (span) {
    span.addEventListener('click', () => copyToClipboard(hash, span));
  }

  return card;
}

function copyToClipboard(text, el) {
  navigator.clipboard.writeText(text).then(() => {
    if (el && el.tagName === 'BUTTON') {
      const originalText = el.textContent;
      el.textContent = 'COPIED';
      el.style.color = 'var(--success)';
      setTimeout(() => {
        el.textContent = originalText;
        el.style.color = '';
      }, 2000);
    } else if (el) {
      const prevColor = el.style.color;
      const prevTitle = el.getAttribute('title') || '';
      el.style.color = 'var(--success)';
      el.setAttribute('title', 'Copied');
      setTimeout(() => {
        el.style.color = prevColor;
        el.setAttribute('title', prevTitle);
      }, 1500);
    }
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

  const btnJson = document.getElementById('downloadJson');
  if (btnJson) {
    btnJson.addEventListener('click', () => {
      const json = JSON.stringify(successfulResults, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      downloadBlob(blob, `virustotal-results-${Date.now()}.json`);
    });
  }

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

  const btnCopyAll = document.getElementById('copyAllHashes');
  if (btnCopyAll) {
    btnCopyAll.addEventListener('click', () => {
      const text = successfulResults.map(r => {
        const fileName = r.meaningful_name || 'unknown';
        const fileType = r.type_description || 'Unknown type';
        return `Name: ${fileName}\nType: ${fileType}\nMD5: ${r.md5}\nSHA1: ${r.sha1}\nSHA256: ${r.sha256}\n`;
      }).join('\n');
      copyToClipboard(text, btnCopyAll);
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