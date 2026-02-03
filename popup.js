document.addEventListener('DOMContentLoaded', () => {
  const hashInput = document.getElementById('hashInput');
  const fetchBtn = document.getElementById('fetchBtn');
  const clearBtn = document.getElementById('clearBtn');
  const statusDiv = document.getElementById('status');
  const settingsLink = document.getElementById('settingsLink');

  // Check if API key is set
  chrome.storage.sync.get(['vtApiKey'], (result) => {
    if (!result.vtApiKey) {
      statusDiv.textContent = '⚠️ Please set your API key in settings first!';
      statusDiv.className = 'status error';
      fetchBtn.disabled = true;
    }
  });

  // Settings link
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  // Clear button
  clearBtn.addEventListener('click', () => {
    hashInput.value = '';
    statusDiv.style.display = 'none';
    hashInput.focus();
  });

  // Fetch button
  fetchBtn.addEventListener('click', async () => {
    const input = hashInput.value.trim();
    
    if (!input) {
      statusDiv.textContent = 'Please enter at least one hash';
      statusDiv.className = 'status error';
      return;
    }

    // Parse hashes from input (split by newlines, commas, or spaces)
    const hashes = input
      .split(/[\n,\s]+/)
      .map(h => h.trim())
      .filter(h => h.length > 0);

    if (hashes.length === 0) {
      statusDiv.textContent = 'No valid hashes found';
      statusDiv.className = 'status error';
      return;
    }

    // Validate hashes
    const md5Regex = /^[a-fA-F0-9]{32}$/;
    const sha1Regex = /^[a-fA-F0-9]{40}$/;
    const sha256Regex = /^[a-fA-F0-9]{64}$/;

    const validHashes = [];
    const invalidHashes = [];

    hashes.forEach(hash => {
      if (md5Regex.test(hash) || sha1Regex.test(hash) || sha256Regex.test(hash)) {
        validHashes.push(hash);
      } else {
        invalidHashes.push(hash);
      }
    });

    if (validHashes.length === 0) {
      statusDiv.textContent = 'No valid hashes found. Please enter MD5, SHA-1, or SHA-256 hashes.';
      statusDiv.className = 'status error';
      return;
    }

    const uniqueValid = Array.from(new Set(validHashes.map(h => h.toLowerCase())));
    const dedupCount = validHashes.length - uniqueValid.length;
    if (invalidHashes.length > 0 || dedupCount > 0) {
      const parts = [];
      if (invalidHashes.length > 0) parts.push(`${invalidHashes.length} invalid`);
      if (dedupCount > 0) parts.push(`${dedupCount} duplicate`);
      statusDiv.textContent = `Warning: ${parts.join(' + ')} hash(es) skipped. Processing ${uniqueValid.length} valid unique hash(es)...`;
      statusDiv.className = 'status info';
    } else {
      statusDiv.textContent = `Processing ${uniqueValid.length} hash(es)...`;
      statusDiv.className = 'status info';
    }

    fetchBtn.disabled = true;
    fetchBtn.textContent = 'Fetching...';

    // Send message to background script to fetch all hashes
    chrome.runtime.sendMessage(
      { action: 'fetchMultipleHashes', hashes: uniqueValid },
      (response) => {
        fetchBtn.disabled = false;
        fetchBtn.textContent = 'Fetch All Hashes';
        
        if (response && response.success) {
          statusDiv.textContent = `✓ Opening results in new tab...`;
          statusDiv.className = 'status success';
          
          // Close popup after a short delay
          setTimeout(() => {
            window.close();
          }, 1000);
        } else {
          statusDiv.textContent = `Error: ${response?.error || 'Unknown error occurred'}`;
          statusDiv.className = 'status error';
        }
      }
    );
  });

  // Allow Ctrl+Enter to fetch
  hashInput.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
      fetchBtn.click();
    }
  });
});
