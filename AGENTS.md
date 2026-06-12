# AGENTS.md — MailSafe Anti-Phishing Chrome Extension

## What does this project do?
Chrome extension (Manifest V3) that detects phishing signals by analyzing
text from web pages and emails using regular expressions and a configurable
threshold system. All analysis runs locally — no data is sent to external servers.

## Stack
- JavaScript (vanilla, no frameworks)
- HTML / CSS for the popup UI
- Chrome Extension APIs (Manifest V3)

## Key files
- `analysis.js` — core phishing detection logic and scoring
- `popup.js` — popup UI logic and analysis orchestration
- `popup.html` — extension popup interface
- `content.js` — content script injected into Gmail / Outlook pages
- `manifest.json` — extension configuration and permissions
- `i18n.js` — internationalization helpers

## How to run and test
1. Open Chrome → `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select this folder
4. Reload the extension after every JS change

## Code conventions
- Modern JavaScript (ES6+)
- Descriptive camelCase function names
- No external dependencies
- Comments in English

## Priorities when modifying code
1. Do not break existing phishing detection
2. Keep performance in mind (runs on visited pages)
3. Clean, extensible code for adding new signals
4. Follow Manifest V3 best practices

## What NOT to do
- Do not use `eval()` or unsanitized `innerHTML` (security risk)
- Do not add permissions to the manifest without documenting why
- Do not use Manifest V2 — this project is V3
