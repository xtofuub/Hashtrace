---

# Hashtrace – VirusTotal Hash Fetcher Chrome Extension

Quickly fetch and analyze MD5, SHA-1, and SHA-256 hashes from VirusTotal, with both single and bulk input methods, all in a sleek, user-friendly interface.

## Features

✨ **Single Hash Lookup** – Highlight any hash on a webpage and press `Ctrl+Shift+X`

📋 **Bulk Hash Lookup** – Paste multiple hashes via the extension popup

📊 **Results Dashboard** – Clean, organized page 

💾 **Export Options** – Copy hashes or export results as JSON or CSV

## Installation

1. Go to the [HashTrace Releases Page](https://github.com/xtofuub/Hashtrace/releases) and download the latest zip file.  
2. Extract the zip file to a folder.  
3. Open Chrome/Brave and go to `chrome://extensions/`  
4. Enable **Developer mode** (toggle in top right).  
5. Click **Load unpacked** and select the extracted folder.  
6. Click the extension icon → **Options**.  
7. Enter your VirusTotal API key and save.

## Get Your API Key

1. Go to [VirusTotal](https://www.virustotal.com/)
2. Sign up or log in
3. Go to **Profile → API Key**
4. Copy and paste into extension settings

## Usage

### Single Hash Lookup

1. Highlight a hash (MD5/SHA-1/SHA-256) on any webpage
2. Press `Ctrl+Shift+X` (Windows/Linux) or `Cmd+Shift+X` (Mac)
3. View results in a sleek modal with copy options

### Bulk Hash Lookup

1. Click the extension icon
2. Paste multiple hashes (one per line)
3. Click **Fetch All Hashes**
4. View results in a dynamic dashboard with:

   * Individual hash details
   * Detection statistics
   * Bulk copy options
   * JSON export

## Example Hashes to Test

```
44748c22baec61a0a3bd68b5739736fa15c479a3b28c1a0f9324823fc4e3fe34
d634c9a618a48ce2b892b9992f7ccbd7
10770be56c62b66af3ff2d48a0ae36c61218e7ac
```

## Tips

* Use bulk copy buttons to grab all hashes of a single type
* Export JSON for integration with other tools or workflows
* Hashtrace respects VirusTotal rate limits with automatic delays

---

