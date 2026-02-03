document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.sync.get(['vtApiKey'], (result) => {
    if (result.vtApiKey) {
      document.getElementById('apiKey').value = result.vtApiKey;
    }
  });
});

document.getElementById('saveBtn').addEventListener('click', () => {
  const apiKey = document.getElementById('apiKey').value.trim();
  const statusDiv = document.getElementById('status');

  if (!apiKey) {
    statusDiv.textContent = 'Please enter an API key';
    statusDiv.className = 'status error';
    statusDiv.style.display = 'block';
    return;
  }

  if (apiKey.length !== 64) {
    statusDiv.textContent = 'Invalid API key format. VirusTotal API keys are 64 characters long.';
    statusDiv.className = 'status error';
    statusDiv.style.display = 'block';
    return;
  }

  chrome.storage.sync.set({ vtApiKey: apiKey }, () => {
    statusDiv.textContent = 'API key saved successfully! You can now use the extension.';
    statusDiv.className = 'status success';
    statusDiv.style.display = 'block';

    setTimeout(() => {
      statusDiv.style.display = 'none';
    }, 3000);
  });
});

document.getElementById('apiKey').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    document.getElementById('saveBtn').click();
  }
});
