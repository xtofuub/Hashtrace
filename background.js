// Debug log to ensure service worker is alive
console.log("Background service worker loaded and running");

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
  console.log("VT Hash Fetcher extension installed/updated");
});

// Listen for keyboard shortcut commands
chrome.commands.onCommand.addListener((command) => {
  console.log("Shortcut command received:", command);

  if (command === "fetch-hashes") {
    console.log("Fetching hashes triggered by keyboard shortcut");

    // Get active tab in current window
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) {
        console.warn("No active tab found");
        return;
      }

      console.log("Active tab found:", tabs[0].id, tabs[0].url);

      // Send message to content script
      chrome.tabs.sendMessage(tabs[0].id, { action: "fetchHashes" }, (response) => {
        if (chrome.runtime.lastError) {
          console.error("Error sending message to content script:", chrome.runtime.lastError);
          console.log("Attempting to inject content script...");

          // Try to inject content script if it's not loaded
          chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            files: ['content.js']
          }).then(() => {
            console.log("Content script injected successfully");
            setTimeout(() => {
              chrome.tabs.sendMessage(tabs[0].id, { action: "fetchHashes" });
            }, 500);
          }).catch(err => {
            console.error("Failed to inject content script:", err);
          });
        } else {
          console.log("Message sent successfully to content script");
        }
      });
    });
  }
});

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("Background received message:", request.action);

  // Fetch a single hash from VirusTotal
  if (request.action === "fetchFromVT") {
    console.log("Fetching single hash from VT:", request.hash);
    fetchHashesFromVT(request.hash)
      .then(data => {
        console.log("Single hash fetched successfully");
        sendResponse({ success: true, data });
      })
      .catch(error => {
        console.error("Error fetching single hash:", error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }

  // Fetch multiple hashes and open results.html
  if (request.action === "fetchMultipleHashes") {
    console.log("Fetching multiple hashes:", request.hashes);

    const original = Array.isArray(request.hashes) ? request.hashes : [];
    const unique = Array.from(new Set(original.map(h => h.toLowerCase())));
    const dedupCount = original.length - unique.length;

    fetchMultipleHashes(unique)
      .then(results => {
        console.log("Multiple hashes fetched successfully");
        // Use storage.local — enriched relation data can be 50-150KB,
        // which URL encoding silently corrupts causing blank results pages
        const storageKey = `hashtrace_results_${Date.now()}`;
        chrome.storage.local.set({ [storageKey]: { results, dedupCount } }, () => {
          chrome.tabs.create({
            url: chrome.runtime.getURL(`results.html?key=${storageKey}`)
          });
        });
        sendResponse({ success: true });
      })
      .catch(error => {
        console.error("Error fetching multiple hashes:", error);
        sendResponse({ success: false, error: error.message });
      });

    return true;
  }
});

// Fetch a single hash from VirusTotal API
async function fetchHashesFromVT(hash) {
  console.log("Starting VT API fetch for hash:", hash);
  const result = await chrome.storage.sync.get(['vtApiKey']);
  const apiKey = result.vtApiKey;

  if (!apiKey) {
    console.error("No API key found");
    throw new Error("Please set your VirusTotal API key in the extension options");
  }

  console.log("Using API key:", apiKey.substring(0, 10) + "...");

  const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    method: 'GET',
    headers: { 'x-apikey': apiKey }
  });

  if (!response.ok) {
    console.error("VT API error:", response.status, response.statusText);
    if (response.status === 404) throw new Error("Hash not found in VirusTotal database");
    if (response.status === 401) throw new Error("Invalid API key. Check your settings");
    throw new Error(`VirusTotal API error: ${response.status}`);
  }

  const data = await response.json();
  const attributes = data.data.attributes;

  const fileResult = {
    md5: attributes.md5,
    sha1: attributes.sha1,
    sha256: attributes.sha256,
    ssdeep: attributes.ssdeep,
    meaningful_name: attributes.meaningful_name,
    size: attributes.size,
    type_description: attributes.type_description,
    last_analysis_stats: attributes.last_analysis_stats,
    relations: {
      // Behavioral / dynamic (observed at runtime)
      ips: [],
      domains: [],
      contacted_urls: [],
      dropped: [],
      // Static strings extracted from the file body
      embedded_domains: [],
      embedded_ips: [],
      embedded_urls: [],
      // Where this file has been seen distributed in the wild
      itw_urls: [],
      // Files that contain or executed this file (parents)
      parents: [],
      overlay_parents: [],
      email_parents: [],
      // Files contained within this file (children)
      bundles: [],
      pe_children: [],
    }
  };

  // Fetch every relation type via dedicated endpoints.
  // The ?relationships= inline expansion is unreliable and capped —
  // dedicated endpoints match what the VT GUI Relations tab actually shows.
  console.log("Fetching all relations via dedicated endpoints...");
  try {
    // These return full file objects with meaningful_name and analysis stats
    const fileRelTargets = [
      { endpoint: 'execution_parents', key: 'parents' },
      { endpoint: 'compressed_parents', key: 'parents' },
      { endpoint: 'pe_resource_parents', key: 'parents' },
      { endpoint: 'overlay_parents', key: 'overlay_parents' },
      { endpoint: 'email_parents', key: 'email_parents' },
      { endpoint: 'bundled_files', key: 'bundles' },
      { endpoint: 'dropped_files', key: 'dropped' },
      { endpoint: 'pe_resource_children', key: 'pe_children' },
    ];

    // These return infrastructure nodes (ip_address, domain, url)
    const infraRelTargets = [
      { endpoint: 'contacted_ips', key: 'ips' },
      { endpoint: 'contacted_domains', key: 'domains' },
      { endpoint: 'contacted_urls', key: 'contacted_urls' },
      { endpoint: 'embedded_domains', key: 'embedded_domains' },
      { endpoint: 'embedded_ips', key: 'embedded_ips' },
      { endpoint: 'embedded_urls', key: 'embedded_urls' },
      { endpoint: 'itw_urls', key: 'itw_urls' },
    ];

    const allTargets = [...fileRelTargets, ...infraRelTargets];

    for (const target of allTargets) {
      const relUrl = `https://www.virustotal.com/api/v3/files/${hash}/${target.endpoint}`;
      const relResponse = await fetch(relUrl, {
        method: 'GET',
        headers: { 'x-apikey': apiKey }
      });

      if (relResponse.ok) {
        const relData = await relResponse.json();
        const fetchedItems = relData.data || [];
        console.log(`${target.endpoint}: ${fetchedItems.length} items`);

        if (fetchedItems.length > 0) {
          const isFileRel = fileRelTargets.some(t => t.endpoint === target.endpoint);
          if (isFileRel) {
            // Merge by id — multiple parent endpoints can overlap
            fetchedItems.forEach(item => {
              const existing = fileResult.relations[target.key].find(e => e.id === item.id);
              if (existing) {
                existing.attributes = item.attributes;
              } else {
                fileResult.relations[target.key].push({
                  id: item.id,
                  type: item.type,
                  attributes: item.attributes || null
                });
              }
            });
          } else {
            // Infrastructure: overwrite with dedicated endpoint data
            fileResult.relations[target.key] = fetchedItems.map(item => ({
              id: item.id,
              type: item.type,
              attributes: item.attributes || null
            }));
          }
        }
      } else if (relResponse.status !== 404) {
        console.warn(`${target.endpoint}: status ${relResponse.status}`);
      }

      await new Promise(resolve => setTimeout(resolve, 300));
    }
  } catch (e) {
    console.error("Relationship enrichment error:", e.message);
  }

  return fileResult;
}

// Fetch multiple hashes sequentially to avoid rate limiting
async function fetchMultipleHashes(hashes) {
  console.log("Fetching multiple hashes sequentially");
  const results = [];

  for (const hash of hashes) {
    console.log(`Processing hash ${results.length + 1}/${hashes.length}:`, hash);
    try {
      const data = await fetchHashesFromVT(hash);
      results.push({ hash, success: true, data });
      console.log(`Successfully fetched hash: ${hash}`);
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      console.error(`Failed to fetch hash ${hash}:`, error.message);
      results.push({ hash, success: false, error: error.message });
    }
  }

  console.log(`Completed fetching ${results.length} hashes`);
  return results;
}