// Content script loaded
console.log("VT Hash Fetcher content script loaded on:", window.location.href);

// Initialize a flag to prevent duplicate message handlers
if (!window.vtMessageListenerInitialized) {
  window.vtMessageListenerInitialized = true;
  
  // Track last message time to prevent rapid duplicate executions
  let lastMessageTime = 0;
  let isProcessing = false;
  
  // Listen for keyboard shortcut messages
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("Content script received message:", request.action);
    
    // Debounce: prevent messages within 1 second of each other
    const now = Date.now();
    if (now - lastMessageTime < 1000) {
      console.log("Ignoring duplicate message - too soon");
      return;
    }
    lastMessageTime = now;
    
    // Prevent concurrent processing
    if (isProcessing) {
      console.log("Already processing a request, ignoring");
      return;
    }
    
    if (request.action === "fetchHashes") {
      isProcessing = true;
      console.log("fetchHashes action triggered by shortcut");
      
      try {
        const selectedText = window.getSelection().toString().trim();
        console.log("Selected text:", selectedText);
        
        if (!selectedText) {
          console.warn("No text selected");
          showNotification("Please highlight one or more hashes!", "error");
          isProcessing = false;
          return;
        }

        // Split highlighted text by space, comma, or newline
        const hashArray = selectedText.split(/[\s,]+/).filter(h => h.trim() !== '');
        console.log("Parsed hash array:", hashArray);

        // Validate hashes (MD5, SHA-1, SHA-256)
        const validHashes = hashArray.filter(h =>
          /^[a-fA-F0-9]{32}$/.test(h) ||
          /^[a-fA-F0-9]{40}$/.test(h) ||
          /^[a-fA-F0-9]{64}$/.test(h)
        );

        console.log("Valid hashes found:", validHashes);

        if (validHashes.length === 0) {
          console.warn("No valid hashes found in selection");
          showNotification("No valid MD5, SHA-1, or SHA-256 hashes selected!", "error");
          isProcessing = false;
          return;
        }

        if (validHashes.length === 1) {
          // Single hash → show modal on page
          console.log("Processing single hash:", validHashes[0]);
          showNotification("Fetching hash from VirusTotal...", "info");
          chrome.runtime.sendMessage({ action: "fetchFromVT", hash: validHashes[0] }, (response) => {
            isProcessing = false;
            if (response && response.success) {
              console.log("Single hash fetched successfully");
              displayHashes(response.data);
            } else {
              console.error("Failed to fetch single hash:", response?.error);
              showNotification(response?.error || "Failed to fetch hash", "error");
            }
          });
        } else {
          // Multiple hashes → send to background to open results.html
          const uniqueValid = Array.from(new Set(validHashes.map(h => h.toLowerCase())));
          const dedupCount = validHashes.length - uniqueValid.length;
          console.log(`Processing ${uniqueValid.length} unique hashes`);
          showNotification(`Fetching ${uniqueValid.length} hashes from VirusTotal${dedupCount > 0 ? ` (${dedupCount} duplicates skipped)` : ''}...`, "info");
          chrome.runtime.sendMessage({ action: "fetchMultipleHashes", hashes: uniqueValid }, (response) => {
            isProcessing = false;
            if (!response || !response.success) {
              console.error("Failed to fetch multiple hashes:", response?.error);
              showNotification(response?.error || "Failed to fetch hashes", "error");
            } else {
              console.log("Multiple hashes fetched successfully");
            }
          });
        }
      } catch (error) {
        console.error("Error processing hash request:", error);
        isProcessing = false;
        showNotification("An error occurred while processing hashes", "error");
      }
    }
    
    // Return true to keep the message channel open for async response
    return true;
  });
  
  console.log("VT Hash Fetcher message listener initialized");
}

// Notification helper - Cleaner, darker, more pleasant
function showNotification(message, type = "info") {
  // Clean up any existing notification first
  const existing = document.getElementById('vt-hash-notification');
  if (existing) {
    existing.remove();
  }

  // Colors for borders/accents
  const accentColor = type === 'error' ? '#FF5252' 
                   : type === 'info' ? '#2DE1FC' 
                   : '#E040FB';
  
  const icon = type === 'error' ? '✕' 
             : type === 'info' ? 'ℹ' 
             : '✓';

  const notification = document.createElement('div');
  notification.id = 'vt-hash-notification';
  
  // Glassmorphism dark style
  notification.style.cssText = `
    position: fixed; top: 24px; right: 24px;
    background: rgba(18, 18, 18, 0.95);
    color: #e0e0e0;
    padding: 12px 20px;
    border-radius: 8px;
    z-index: 2147483647; /* Max z-index */
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
    font-weight: 500;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    border: 1px solid #333;
    border-left: 3px solid ${accentColor};
    display: flex;
    align-items: center;
    gap: 12px;
    opacity: 0;
    transform: translateY(-10px);
    transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    pointer-events: none; /* Don't block clicks underneath initially */
  `;
  
  notification.innerHTML = `
    <span style="color: ${accentColor}; font-weight: bold; font-size: 16px; line-height: 1;">${icon}</span>
    <span>${message}</span>
  `;
  
  document.body.appendChild(notification);

  // Trigger animation
  requestAnimationFrame(() => {
    notification.style.opacity = '1';
    notification.style.transform = 'translateY(0)';
  });

  // Auto-remove notification after 3 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.style.opacity = '0';
      notification.style.transform = 'translateY(-10px)';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 300);
    }
  }, 3500);
}

// Modal display for single hash - Cleaner UI
function displayHashes(data) {
  console.log("Displaying hash data in modal");
  
  // Clean up any existing modal first
  const existingModal = document.getElementById('vt-hash-modal');
  const existingBackdrop = document.getElementById('vt-hash-backdrop');
  
  if (existingModal) existingModal.remove();
  if (existingBackdrop) existingBackdrop.remove();

  const modal = document.createElement('div');
  modal.id = 'vt-hash-modal';
  
  // Refined Dark UI for Modal
  modal.style.cssText = `
    position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
    background: #0F0F0F;
    border-radius: 12px;
    z-index: 2147483647;
    box-shadow: 0 24px 48px rgba(0,0,0,0.6), 0 0 0 1px #222;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    width: 90%; max-width: 650px;
    max-height: 85vh; overflow-y: auto;
    color: #e0e0e0;
    outline: none;
    opacity: 0;
    transition: opacity 0.2s ease;
  `;

  const isMalicious = data.last_analysis_stats.malicious > 0;
  
  // Status Colors
  const statusColor = isMalicious ? '#FF5252' : '#69F0AE';
  const statusBg = isMalicious ? 'rgba(255, 82, 82, 0.1)' : 'rgba(105, 240, 174, 0.1)';
  const statusBorder = isMalicious ? 'rgba(255, 82, 82, 0.2)' : 'rgba(105, 240, 174, 0.2)';
  const statusIcon = isMalicious ? '⚠️' : '🛡️';
  const statusText = isMalicious ? 'THREAT DETECTED' : 'CLEAN';

  const fileName = data.meaningful_name || 'Unknown File';
  const truncatedFileName = fileName.length > 60 ? fileName.substring(0,57) + '...' : fileName;

  modal.innerHTML = `
    <!-- Header -->
    <div style="padding: 20px 24px; border-bottom: 1px solid #222; display: flex; justify-content: space-between; align-items: center;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <div style="width: 32px; height: 32px; background: #1a1a1a; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: #2DE1FC; font-weight: 800; font-size: 14px;">VT</div>
        <h2 style="margin: 0; color: #fff; font-size: 16px; font-weight: 600;">Analysis Result</h2>
      </div>
      <button id="vt-close-modal" style="background: transparent; border: none; color: #666; font-size: 24px; cursor: pointer; padding: 0; line-height: 1; transition: color 0.2s;">&times;</button>
    </div>

    <!-- Content -->
    <div style="padding: 24px;">
      
      <!-- Status Banner -->
      <div style="background: ${statusBg}; border: 1px solid ${statusBorder}; border-radius: 8px; padding: 16px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px;">
        <div style="font-size: 24px;">${statusIcon}</div>
        <div>
          <div style="color: ${statusColor}; font-weight: 700; font-size: 14px; letter-spacing: 0.5px; margin-bottom: 4px;">${statusText}</div>
          <div style="font-size: 13px; color: #ccc;">
            <strong>${data.last_analysis_stats.malicious}</strong> security vendors flagged this file as malicious
          </div>
        </div>
      </div>

      <!-- File Info -->
      <div style="margin-bottom: 24px;">
        <div style="font-size: 12px; text-transform: uppercase; color: #666; font-weight: 600; margin-bottom: 8px; letter-spacing: 0.5px;">File Details</div>
        <div style="background: #161616; border: 1px solid #222; border-radius: 8px; padding: 16px;">
          <div style="margin-bottom: 12px;">
            <div style="color: #888; font-size: 12px; margin-bottom: 4px;">Name</div>
            <div style="color: #fff; font-size: 14px; word-break: break-all; font-family: 'SF Mono', 'Segoe UI Mono', 'Roboto Mono', monospace;">${truncatedFileName}</div>
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
            <div>
              <div style="color: #888; font-size: 12px; margin-bottom: 4px;">Size</div>
              <div style="color: #fff; font-size: 14px;">${formatBytes(data.size)}</div>
            </div>
            <div>
              <div style="color: #888; font-size: 12px; margin-bottom: 4px;">Type</div>
              <div style="color: #fff; font-size: 14px;">${data.type_description || 'Unknown'}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Hashes -->
      <div style="margin-bottom: 24px;">
        <div style="font-size: 12px; text-transform: uppercase; color: #666; font-weight: 600; margin-bottom: 8px; letter-spacing: 0.5px;">Hashes</div>
        <div style="display: flex; flex-direction: column; gap: 10px;">
          ${['md5','sha1','sha256'].map(h => `
            <div style="background: #161616; border: 1px solid #222; border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; justify-content: space-between; gap: 12px;">
              <div style="overflow: hidden;">
                <div style="color: #666; font-size: 10px; font-weight: 700; text-transform: uppercase; margin-bottom: 2px;">${h}</div>
                <div style="color: #ccc; font-size: 12px; font-family: 'SF Mono', 'Segoe UI Mono', 'Roboto Mono', monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${data[h]}</div>
              </div>
              <button class="copy-btn" data-hash="${data[h]}" style="background: transparent; border: 1px solid #333; color: #888; border-radius: 6px; padding: 6px 12px; font-size: 11px; font-weight: 600; cursor: pointer; transition: all 0.2s; flex-shrink: 0;">COPY</button>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Footer Action -->
      <a href="https://www.virustotal.com/gui/file/${data.sha256}" target="_blank" style="display: flex; align-items: center; justify-content: center; width: 100%; background: #2DE1FC; color: #000; text-decoration: none; padding: 12px; border-radius: 8px; font-weight: 600; font-size: 14px; transition: transform 0.1s;">
        View Full Analysis Report ↗
      </a>
    </div>
  `;

  const backdrop = document.createElement('div');
  backdrop.id = 'vt-hash-backdrop';
  backdrop.style.cssText = `
    position: fixed; top:0; left:0; width:100%; height:100%;
    background: rgba(0,0,0,0.6); z-index: 2147483646;
    backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px);
    opacity: 0; transition: opacity 0.2s ease;
  `;

  document.body.appendChild(backdrop);
  document.body.appendChild(modal);

  // Animate in
  requestAnimationFrame(() => {
    modal.style.opacity = '1';
    backdrop.style.opacity = '1';
  });

  // Create cleanup function
  const cleanupModal = () => {
    modal.style.opacity = '0';
    backdrop.style.opacity = '0';
    setTimeout(() => {
      if (modal.parentNode) modal.remove();
      if (backdrop.parentNode) backdrop.remove();
    }, 200);
  };

  // Close modal handlers
  document.getElementById('vt-close-modal').addEventListener('click', cleanupModal);
  backdrop.addEventListener('click', cleanupModal);

  // Close on Escape key
  const escapeHandler = (e) => {
    if (e.key === 'Escape') {
      cleanupModal();
      document.removeEventListener('keydown', escapeHandler);
    }
  };
  document.addEventListener('keydown', escapeHandler);

  // Copy functionality with visual feedback
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.getAttribute('data-hash')).then(() => {
        const originalText = btn.textContent;
        const originalBorder = btn.style.borderColor;
        const originalColor = btn.style.color;
        
        btn.textContent = 'COPIED';
        btn.style.borderColor = '#2DE1FC';
        btn.style.color = '#2DE1FC';
        
        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.borderColor = originalBorder;
          btn.style.color = originalColor;
        }, 1500);
      }).catch(err => {
        console.error("Copy failed:", err);
        showNotification("Failed to copy", "error");
      });
    });
    
    // Add hover effect via JS since inline styles make pseudo-classes hard
    btn.addEventListener('mouseenter', () => {
        if(btn.textContent !== 'COPIED') {
            btn.style.borderColor = '#666';
            btn.style.color = '#fff';
        }
    });
    btn.addEventListener('mouseleave', () => {
        if(btn.textContent !== 'COPIED') {
            btn.style.borderColor = '#333';
            btn.style.color = '#888';
        }
    });
  });
}

function formatBytes(bytes) {
  if (bytes===0) return '0 Bytes';
  const k = 1024, sizes=['Bytes','KB','MB','GB'];
  const i = Math.floor(Math.log(bytes)/Math.log(k));
  return Math.round(bytes/Math.pow(k,i)*100)/100 + ' ' + sizes[i];
}
