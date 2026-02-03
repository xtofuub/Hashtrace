# VirusTotal Hash Fetcher - Chrome Extension

Quickly fetch MD5, SHA-1, and SHA-256 hashes from VirusTotal with multiple input methods.

## Features

✨ **Single Hash Lookup** - Highlight any hash on a webpage and press `Ctrl+Shift+X`
📋 **Bulk Hash Lookup** - Click extension icon and paste multiple hashes
🔄 **Sequential Clipboard** - Copy all 3 hash types and paste them one by one
📊 **Results Dashboard** - View all results in a clean, organized page
💾 **Export Options** - Copy all hashes or export as JSON

## Installation

1. Extract the zip file to a folder
2. Open Chrome and go to `chrome://extensions/`
3. Enable **Developer mode** (toggle in top right)
4. Click **Load unpacked**
5. Select the extracted folder
6. Click the extension icon → Options
7. Enter your VirusTotal API key and save

## Get Your API Key

1. Go to https://www.virustotal.com/
2. Sign up/login
3. Profile → API Key
4. Copy and paste into extension settings

## Usage

### Method 1: Quick Lookup (Single Hash)
1. Highlight any hash (MD5/SHA-1/SHA-256) on any webpage
2. Press `Ctrl+Shift+X` (Windows/Linux) or `Cmd+Shift+X` (Mac)
3. View results in popup with sequential copy feature

### Method 2: Bulk Lookup (Multiple Hashes)
1. Click the extension icon
2. Paste multiple hashes (one per line)
3. Click "Fetch All Hashes"
4. View all results in a new tab with:
   - Individual hash details
   - Detection statistics
   - Bulk copy options (all MD5s, all SHA-1s, all SHA-256s)
   - JSON export

## Example Hashes to Test

```
44748c22baec61a0a3bd68b5739736fa15c479a3b28c1a0f9324823fc4e3fe34
d634c9a618a48ce2b892b9992f7ccbd7
10770be56c62b66af3ff2d48a0ae36c61218e7ac
```

## Tips

- Results page includes buttons to copy all hashes of the same type
- Export results as JSON for further processing
- The extension respects VirusTotal rate limits with automatic delays
