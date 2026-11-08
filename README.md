# TRUSTGUARD
## AI-Powered Web Threat Detection & Digital Trust Intelligence

TRUSTGUARD is a clean, modern, and user-friendly cybersecurity platform built with **Python Flask**, **SQLite**, and vanilla **HTML/CSS/JavaScript**. It empowers everyday users to check links, emails, SMS messages, and files for digital threats, while providing college students and evaluators with a transparent, rule-based architecture to demonstrate security concepts without requiring expensive paid APIs.

---

## 🎨 Color Theme & Design Standards

Adhering strictly to the minimal, human-friendly design system:

| Element | Color | Hex Code |
| :--- | :--- | :--- |
| **Main Background** | Pure White | `#FFFFFF` |
| **Primary Theme** | Dark Navy Blue | `#102A43` |
| **Secondary Background** | Soft Light Blue | `#F1F6FB` |
| **Buttons & Main Text** | Dark Navy Blue | `#102A43` |
| **Secondary / Subtext** | Neutral Slate Grey | `#627D98` |
| **Safe Status** | Emerald Green | `#0F9D58` |
| **Suspicious Status** | Alert Orange | `#DD6B20` |
| **Dangerous Status** | Crimson Red | `#DC3545` |

---

## 🛠️ Security Technologies & Libraries

TRUSTGUARD requires **no paid APIs or subscriptions**. All intelligence is computed in real time using Python's standard security modules and lightweight networking:

1. **`ssl`**: Performs live TLS/SSL handshakes to verify certificate authorities (CAs), expiration countdowns, subject names, and cryptographic cipher suites.
2. **`socket`**: Performs host and DNS resolution, reverse IP lookups, and direct port connectivity tests.
3. **`requests`**: Checks live HTTP status codes, redirection chains, and critical security headers (`Strict-Transport-Security`, `X-Frame-Options`, `Content-Security-Policy`).
4. **`ipaddress`**: Differentiates legitimate domain names from bare IP addresses, identifying private LANs, loopbacks, and unallocated IP ranges.
5. **`hashlib`**: Generates cryptographic digital fingerprints (MD5, SHA-1, SHA-256) for file integrity checks and compares them against known threat signatures.
6. **`sqlite3`**: Maintains local persistent audit logs of all scans with filtering and statistics tracking.

---

## 🚀 Key Features

### 1. Website & URL Safety Scanner
- Validates URL syntax, protocol (HTTP vs HTTPS), and domain authenticity.
- Detects phishing heuristics: excessive subdomains (`paypal.com.verify.xyz`), raw IP addresses in links, high-risk TLDs (`.xyz`, `.top`, `.loan`), and brand impersonation hyphens.
- Displays a 0–100 Trust Score with plain-language recommendations and an expandable technical checklist for examiners.

### 2. Phishing & Scam Message Detector
- Analyzes pasted SMS, email, or chat text for social engineering tricks:
  - **Urgency tactics:** "within 24 hours", "account suspended", "act now".
  - **Financial lures:** "lottery winner", "crypto giveaway", "$5,000 prize".
  - **Credential traps:** "confirm your password", "enter your OTP".
  - **Hidden links:** Detects URL shorteners (`bit.ly`, `tinyurl`) and suspicious domain links.

### 3. File Hash & Malware Integrity Checker
- **File Upload:** Computes cryptographic hashes (MD5, SHA-1, SHA-256) instantly.
- **Direct Hash Lookup:** Allows pasting any 32, 40, or 64-character hash string.
- Flags known test threats (e.g., EICAR antivirus test signatures, WannaCry indicators), deceptive double extensions (`invoice.pdf.exe`), and dangerous script formats.

### 4. Direct SSL / TLS Certificate Inspector
- Connects directly to any domain on port 443.
- Reads issuer organization (e.g., Let's Encrypt, DigiCert, Google Trust Services), validity dates, days until expiry, and TLS protocol version.

### 5. Threat Intelligence History & Audit Log
- Automatically logs every inspection to `trustguard.db` (SQLite).
- Search, filter by scan type (URL, Message, File, SSL) or status (Safe, Suspicious, Dangerous).
- 1-click log refresh and reset capability.

### 6. Interactive Cybersecurity Guide
- Bite-sized educational cards explaining how to spot phishing URLs, 5 red flags in scam SMS, why SSL encryption matters, and how cryptographic hashes work.

---

## 📁 Project Structure

```
assign2/
├── app.py                 # Flask server & REST API endpoints
├── scanner.py             # Core security engine (ssl, socket, hashlib, ipaddress, requests)
├── database.py            # SQLite database interface & audit logging
├── test_suite.py          # Automated verification test suite (5/5 tests passing)
├── requirements.txt       # Python dependencies (Flask, requests)
├── README.md              # Project documentation and demo script
├── templates/
│   └── index.html         # Modern single-page web application UI
└── static/
    ├── css/
    │   └── style.css      # Custom stylesheet conforming to requested color theme
    └── js/
        └── app.js         # Vanilla JavaScript client logic and API interactions
```

---

## 💻 How to Run

### Step 1: Install Dependencies
Open your terminal inside the project directory:
```bash
pip install -r requirements.txt
```

### Step 2: Start the Web Application
```bash
python app.py
```

### Step 3: Open in Your Web Browser
Navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Running the Automated Test Suite

To verify all security functions and database operations automatically:
```bash
python test_suite.py
```

Expected output:
```
============================================================
 TRUSTGUARD TEST SUITE - CYBERSECURITY ENGINE VERIFICATION
============================================================
 [PASS] Home Page & UI template loaded
 [PASS] URL Phishing detection: Status=DANGEROUS (Score: 5)
 [PASS] Raw IP URL detection: HostType=Private IP (Local Network)
 [PASS] Scam Message detection: Status=DANGEROUS (Triggers: 3)
 [PASS] Normal clean message verified: Score=100 (SAFE)
 [PASS] Known malware signature detected via hashlib
 [PASS] Safe file upload: SHA256=...
 [PASS] Database Persistence: Scans recorded in SQLite
----------------------------------------------------------------------
Ran 5 tests in 0.33s

OK
```

---

## 🎓 College Demonstration Guide

During your presentation or viva, you can use the **1-Click Preset Buttons** built into the interface to show the examiner each scenario:

### Demo Scenario 1: Legitimate Website
1. Go to **Website Scanner**.
2. Click the preset sample **`google.com (Safe)`** or type `https://www.google.com`.
3. **Show the Examiner:**
   - Status badge turns **Green (SAFE)** with a high Trust Score.
   - Explain how Python's `ssl` verified Google Trust Services and active HTTPS.
   - Click *Technical Security Checks* to reveal the live IP address and security headers.

### Demo Scenario 2: Phishing Attack Link
1. Click the preset sample **`paypal-verify.xyz (Phishing)`**.
2. **Show the Examiner:**
   - Status badge turns **Red (DANGEROUS)** with a low Trust Score.
   - Point out the identified threat flags: Suspicious `.xyz` TLD, 4 hyphens in domain, sensitive authentication keywords (`login`, `verification`), and unencrypted HTTP.

### Demo Scenario 3: Scam SMS / Phishing Message
1. Switch to **Message Scam Detector**.
2. Click **`Fake Netflix Urgent Notice`**.
3. **Show the Examiner:**
   - Flagged as **DANGEROUS**.
   - Explain how the rule engine caught the urgency trigger (`within 24 hours`), brand impersonation (`Netflix`), and suspicious link extension.

### Demo Scenario 4: Malware Hash Check
1. Switch to **File & Hash Checker**.
2. Click the preset chip **`EICAR Antivirus Test (MD5)`**.
3. **Show the Examiner:**
   - Flagged as **DANGEROUS** (Score: 0).
   - Explains how antivirus software identifies known viruses by matching hash digests without having to run dangerous code.

### Demo Scenario 5: Audit Log & Database
1. Switch to **Scan History**.
2. Show that every demonstration test you just ran is saved in the SQLite table with its timestamp, trust score, and summary.
