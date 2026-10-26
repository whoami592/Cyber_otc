# 🕵️ CYBER OTC — All-In-One OSINT Reconnaissance Toolkit

**Coded by: Mr Sabaz Ali Khan (Cyber Security Engineer)**

Cyber OTC is a Python-based OSINT (Open Source Intelligence) toolkit inspired by
classic recon tools like Mr.Holmes — rebuilt from scratch with its own codebase,
banner and branding. It gathers publicly available information about usernames,
domains, and phone numbers, and generates Google dork queries for recon work.

## ✨ Features

| # | Module | Description |
|---|--------|-------------|
| 1 | **Username OSINT** | Checks a username across 25+ platforms (GitHub, Instagram, Twitter/X, TikTok, LinkedIn, Telegram, Reddit, etc.) using concurrent HTTP requests |
| 2 | **Domain / WHOIS / DNS Recon** | Resolves IP, reverse DNS, WHOIS registrar/creation/expiry data, and HTTP server fingerprint |
| 3 | **Phone Number OSINT** | Validates a number, and reports region, carrier, timezone, and line type via `phonenumbers` |
| 4 | **Google Dork Generator** | Builds ready-to-use dork queries (login panels, exposed files, git leaks, LinkedIn staff, subdomains, etc.) for a given target |

All results are saved automatically as timestamped JSON reports in `cyberotc_reports/`.

## 📦 Installation

```bash
git clone <your-repo-url> CyberOTC
cd CyberOTC
pip install -r requirements.txt
python3 cyber_otc.py
```

The tool works with reduced functionality even without the optional libraries
(`requests`, `python-whois`, `phonenumbers`) — it falls back to the standard
library where possible and tells you what's missing.

## 🚀 Usage

```bash
python3 cyber_otc.py
```

Then pick a module from the menu:

```
[1] Username OSINT        (scan 25+ platforms)
[2] Domain / WHOIS / DNS Recon
[3] Phone Number OSINT
[4] Google Dork Generator
[5] Exit
```

## ❗ Disclaimer

This tool is built strictly for **educational purposes and authorized security
research**. Only use it against targets you own or have explicit written
permission to test. The author, Mr Sabaz Ali Khan, assumes no liability for
any misuse of this software.

## 🧑‍💻 Credit

**Coded by: Mr Sabaz Ali Khan — Cyber Security Engineer**
