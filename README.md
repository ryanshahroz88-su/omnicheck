# OmniCheck — Universal Safety Checker

A defensive GUI tool that checks **links, emails, files and messages** and
tells you, in plain words, whether they are safe to open. Python 3 standard
library only — no pip packages, no install step.

## Run it

```bash
python3 app.py
```

Then open http://127.0.0.1:8000 in your browser.

## What it checks

### Link tab
URL tricks (@ trick, // trick, punycode/homograph look-alikes, look-alike
brands, shorteners, IP-address URLs, unusual ports, open-redirect
parameters, data:/javascript: schemes), IP-grabber services, redirect chain
with final destination, domain age via RDAP (under 7 days old can never
score Safe; under 30 days old can never score Safe either), DNS A/MX/NS,
SPF/DKIM/DMARC, certificate validity, and a page content scan (password
forms, forms posting elsewhere, urgency language). Live threat databases:
PhishTank (verified-online feed, no key needed), Google Safe Browsing and
VirusTotal (free keys — see below). Private/internal addresses are refused
(SSRF protection).

### Email tab
Paste the full email (headers + body). Checks From vs the Received chain,
SPF / DKIM / DMARC results, links inside the email (each one link-checked),
pressure/scam wording, brand impersonation, and risky attachments.

### File tab
Upload a picture, PDF, Word/Excel/PowerPoint document, zip or any file
(max 32 MB). The file is **never executed** — static analysis only.
Checks: real type from magic bytes (flags a renamed file, e.g. an .exe
called .jpg), SHA-256 hash + VirusTotal hash lookup, PDF JavaScript /
launch / embedded files / actions, Office macros and external links,
image metadata, zip contents (programs, scripts, nested archives), and
links hidden inside the file's text.

### Text tab
Paste a message, text or emoji. Checks scam/phishing wording, embedded
links (link-checked), hidden Unicode tricks (invisible characters,
right-to-left override, look-alike letters) and misleading emoji (fake
verification/trust symbols). Emojis are plain Unicode and cannot run
code — only the tricks around them are dangerous. A sticker is checked
as a picture: save it and check it in the File tab.

## Risk score

0–100 + verdict: **Safe to open** (0–10), **Open with caution** (11–49),
**Do NOT open** (50+). Every finding has a plain-language reason, and a
score above 10 shows a "How to confirm before opening" safety guide.
A clean result is labelled **NO KNOWN-BAD FOUND**.

## Live threat databases (free keys)

- **PhishTank** — live, no key needed.
- **Google Safe Browsing** — needs a free API key:
  `GOOGLE_SAFE_BROWSING_API_KEY`
- **VirusTotal** (70+ antivirus engines) — needs a free API key:
  `VIRUSTOTAL_API_KEY`

Set them before starting the app, e.g.:

```bash
GOOGLE_SAFE_BROWSING_API_KEY=your-key VIRUSTOTAL_API_KEY=your-key python3 app.py
```

Until a key is set, that row honestly says **"not set up"** instead of
faking a result. When the VirusTotal check did not run, the score is
captioned **"risk from built-in checks only — antivirus check not run"**.

## Honest limits

No tool can prove a link or file 100% safe, and a new threat can hide
from every scanner. A clean result means nothing *known-bad* was found.
If a check could not run, the report says so instead of inventing a
result.

## Safety

- Uploaded files are never executed — read-only static analysis.
- Private/internal addresses are refused (SSRF protection).
- Nothing is stored on the server — history lives in your browser
  session only.
- The tool only reads what you give it. It never creates phishing
  pages, never captures credentials, never scans ports.

## Files

- `app.py` — the whole tool (Python 3 stdlib only)
- `README.md` — this file
- `DEMO.md` — 30-second demo script
