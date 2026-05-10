# BurpJSLinkFinder Enhanced - Link & Sensitive Data Finder

Enhanced Burp Suite extension for passively scanning JavaScript files to find endpoint links and sensitive data (credentials, tokens, API keys, etc.).

## 🚀 Features

### Link Discovery
- **Endpoint Detection**: Finds API endpoints, routes, and URLs within JavaScript files
- **Multiple Formats**: Detects full URLs, relative paths, handlers, and file references
- **Template Literals**: Supports ES6 template literals (backticks)
- **Smart Filtering**: Excludes common libraries (jQuery, Google Analytics, etc.)

### Sensitive Data Detection 🆕
- **API Keys**: Detects API keys when explicitly named (`api_key`, `apikey`, `apiKey`, etc.)
- **JWT Tokens**: Identifies JSON Web Tokens
- **OAuth/Bearer Tokens**: Finds OAuth and Bearer authentication tokens
- **AWS Credentials**: Detects AWS Access Keys and Secret Keys, including temporary key IDs
- **Database Connections**: Finds hardcoded database connection strings, including `mongodb+srv` and `redis`
- **Private Keys**: Detects RSA, DSA, EC, and OpenSSH private keys
- **GitHub Tokens**: Identifies classic, OAuth, installation, refresh, and fine-grained PAT tokens
- **GitLab Tokens**: Identifies personal, deploy, runner, CI, trigger, feed, agent, workspace, and SCIM tokens
- **Google Credentials**: Detects Google API keys and OAuth secrets/tokens
- **Slack Secrets**: Finds Slack tokens and incoming webhooks
- **Stripe Keys**: Finds Stripe API keys (live, test, and restricted)
- **OpenAI Keys**: Detects OpenAI project, service account, admin, and standard API keys
- **Anthropic Keys**: Detects Anthropic API keys
- **Hardcoded Passwords**: Detects hardcoded passwords
- **URLs with Credentials**: Finds URLs containing embedded credentials
- **Email Addresses**: Identifies email addresses
- **Generic Secrets**: Catches other credential patterns
- **Hex Hashes**: Detects standalone MD5, SHA1, and SHA256-style hex values

### Improvements Over Original
- ✅ Enhanced regex patterns for better link detection
- ✅ Support for `.ashx` handlers and endpoints without extensions
- ✅ Detection of JavaScript files by MIME type (not just `.js` extension)
- ✅ Detection of files served from paths ending in `/js`
- ✅ Comprehensive sensitive data detection
- ✅ False positive filtering for common JavaScript function names
- ✅ Separate Burp issues for sensitive data findings
- ✅ Improved UI with severity indicators

## 📋 Requirements

- **Burp Suite Professional** (required)
- **Jython** (Jython Standalone JAR file)

## 🔧 Installation

1. **Download Jython**:
   - Visit https://www.jython.org/download
   - Download the Jython Standalone JAR (e.g., `jython-standalone-2.7.3.jar`)

2. **Configure Jython in Burp**:
   - Open Burp Suite → **Extender** → **Options** tab
   - Under **Python environment**, select **Location of Jython standalone JAR file**
   - Click **Select file** and choose your Jython JAR file

3. **Load the Extension**:
   - Go to **Extender** → **Extensions** tab
   - Click **Add**
   - Select **Python** as extension type
   - Click **Select file** and choose `FransLinkfinder.py`
   - The extension should load successfully

## 📖 Usage

### Basic Configuration

1. **Configure Scanner Settings**:
   - **Scanner** → **Live Scanning**
   - **Live Passive Scanning**: Use suite scope
   - **Live Active Scanning**: Disabled (optional)

2. **Navigate or Proxy Traffic**:
   - Browse the target application or proxy traffic through Burp
   - JavaScript files will be automatically analyzed

3. **View Results**:
   - **BurpJSLinkFinder Tab**: View all detected links and sensitive data
   - **Target → Issues**: See separate issues for:
     - "Linkfinder Analysed JS files" (Information)
     - "Sensitive Data Found in JavaScript" (High/Medium/Low)

### Configuration Options

Edit `FransLinkfinder.py` to customize:

**Exclude JavaScript Files** (line ~34):
```python
JSExclusionList = ['jquery', 'google-analytics', 'gpt.js']
```

**Enable/Disable Sensitive Data Detection** (line ~38):
```python
ENABLE_SENSITIVE_DATA_DETECTION = True  # Set to False to disable
```

**Customize Sensitive Data Patterns**:
Edit the `SENSITIVE_PATTERNS` list in the `SensitiveDataAnalyzer` class to add or modify detection patterns.

## 📸 Example Output

```
[+] Valid URL found: https://example.com/app.js
	[LINK] 0 - /api/users
	[LINK] 1 - https://api.example.com/v1/data
	[!] Informacion sensible detectada:
	  [HIGH] API Key: sk_live_abc123...
	  [HIGH] JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🔍 Detection Patterns

### Links Detected
- Full URLs: `https://api.example.com/endpoint`
- Relative paths: `/api/users`, `../config.json`
- File references: `utils.js`, `config.php`

### Sensitive Data Detected
- API Keys: `api_key="abc123..."` (only when explicitly named)
- JWT Tokens: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`
- AWS Keys: `AKIA...`, `ASIA...`, `aws_secret_access_key="..."`
- Database URLs: `mysql://...`, `mongodb+srv://...`, `redis://...`
- Private Keys: `-----BEGIN RSA PRIVATE KEY-----...`, `-----BEGIN OPENSSH PRIVATE KEY-----...`
- GitHub Tokens: `ghp_...`, `gho_...`, `github_pat_...`
- GitLab Tokens: `glpat-...`, `gldt-...`, `glrt-...`
- Google Credentials: `AIza...`, `GOCSPX-...`, `ya29....`
- Slack Secrets: `xoxb-...`, `https://hooks.slack.com/services/...`
- Stripe Keys: `sk_live_...`, `pk_test_...`, `rk_live_...`
- OpenAI Keys: `sk-proj-...`, `sk-svcacct-...`
- Anthropic Keys: `sk-ant-...`

## 🛠️ Technical Details

### Supported MIME Types
- `application/javascript`
- `application/x-javascript`
- `text/javascript`
- `script` (Burp's generic type)

### File Extensions Detected
- `.js`, `.mjs`, `.cjs`, `.jsx`, `.ashx`, `.php`, `.asp`, `.aspx`, `.jsp`, `.json`, `.action`, `.html`, `.htm`, `.ts`, `.tsx`, `.vue`, `.txt`, `.xml`, `.yaml`, `.yml`, `.config`, `.map`
- Handlers without extensions: `Handler?param=value`

### False Positive Filtering
The extension filters out common JavaScript function names and patterns to reduce false positives:
- React lifecycle methods (`componentWillUnmount`, etc.)
- Event handlers (`innerSliderRefHandler`, etc.)
- Common variable names (`example.com`, `localhost`, `test`, `demo`, etc.)

## 📝 Changelog

### Version 2.0.0 (Enhanced)
- ✨ Added comprehensive sensitive data detection
- 🔧 Improved regex patterns for better link detection
- 🎯 Added support for `.ashx` handlers and endpoints without extensions
- 📊 Detection by MIME type (not just file extension)
- 🚫 Enhanced false positive filtering
- 🎨 Separate Burp issues for sensitive data findings
- 📱 Support for template literals (backticks)
- 🐛 Fixed encoding issues

### Version 1.0.0 (Original)
- Initial release with link detection
- Export functionality
- Exclusion list support

## 🙏 Credits

### Original Version
- **Original Author**: Frans Hendrik Botes (2019)
- **Original Repository**: Based on BurpJSLinkFinder
- **LinkFinder Credit**: Regex patterns inspired by [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)

### Enhanced Version
- **Enhanced by**: [Your Name/Organization]
- **Improvements**: Sensitive data detection, enhanced patterns, better filtering

## 📄 License

Original work copyright (c) 2019 Frans Hendrik Botes.
This repository contains a modified/enhanced version and is not the original release.

This project is provided as-is for security research and educational purposes.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Use responsibly and only on systems you own or have explicit permission to test.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📧 Support

For issues or questions, please open an issue on the GitHub repository.

---

**Note**: This repository contains a modified/enhanced version of BurpJSLinkFinder and is not the original release. It preserves the original idea and adds sensitive data detection and broader pattern coverage.
