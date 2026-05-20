# 🔍 EmailSleuth — Email OSINT Toolkit

> A modular, command-line email intelligence tool for security researchers and investigators.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

EmailSleuth performs passive, non-intrusive reconnaissance on any email address — aggregating publicly available intelligence into a clean terminal report and exportable HTML file.

---

## ⚡ Features

| Module | Description |
|--------|-------------|
| 📡 DNS Analyzer | MX records, SPF and DMARC policy evaluation |
| 🌐 WHOIS Lookup | Registrar, org, country, domain age with phishing flag |
| 🔓 Breach Intelligence | k-Anonymity hash check via HIBP + LeakCheck public API |
| 📧 Disposable Detector | Checks against 100,000+ known throwaway domains |
| 📨 SMTP Validator | Real SMTP handshake to verify email existence without sending |
| 👤 Gravatar OSINT | Avatar, linked accounts, and public profile extraction |
| 📄 HTML Report | Full dark-themed exportable report with risk scoring |

---

## 🛡️ Risk Scoring Engine

EmailSleuth automatically calculates a **risk score (0–100)** based on:

- Missing SPF record → +20
- Missing DMARC record → +20
- Domain age under 180 days → +25
- Email hash found in breach dumps → +20
- Disposable email domain → +30
- Found in public breach database → +15

Risk levels: `Low` / `Medium` / `High`

---

## 🚀 Installation

```bash
git clone https://github.com/Shourj/emailsleuth.git
cd emailsleuth
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

## 🖥️ Usage

```bash
python main.py
```

Enter any email address when prompted. EmailSleuth will run all modules and generate:
- A formatted terminal report
- An HTML report saved as `report_<email>.html`

---

## 🔬 How It Works

### k-Anonymity Breach Detection
EmailSleuth never sends your full email to any external API. Instead it uses the **k-anonymity model** — hashing the email with SHA-1 and sending only the first 5 characters to the HaveIBeenPwned Pwned Passwords API. The response is matched locally. This is the same technique used by browsers like Firefox and Chrome.

### SMTP Validation
EmailSleuth opens a real SMTP connection to the target domain's mail server and performs a full handshake up to the `RCPT TO` command — the point at which the server confirms or denies whether the address exists — without ever sending an actual email. Note: large providers like Gmail intentionally time out this check as an anti-enumeration measure.

### Passive Reconnaissance Only
All checks are read-only and use publicly available data sources. No emails are sent, no accounts are accessed, and no intrusive scans are performed.

---

## ⚖️ Legal & Ethical Use

This tool is intended for:
- Security researchers
- Penetration testers (with written authorization)
- Individuals checking their own email exposure
- SOC analysts and threat intelligence workflows

**Do not use this tool against emails you do not have authorization to investigate.**

---

## 📁 Project Structure