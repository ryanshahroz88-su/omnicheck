# OmniCheck — 30-second demo

Run `python3 app.py`, open http://127.0.0.1:8000, then:

1. **Link — safe:** paste `https://www.google.com` → **0, Safe to open**,
   "NO KNOWN-BAD FOUND".
2. **Link — fake:** paste `https://secure-paypal-verify.top/signin` →
   **100, Do NOT open** (look-alike brand, new domain, listed in PhishTank).
3. **Text — scam:** click "Try a prize scam message" → **SUSPICIOUS**
   (prize wording, fake trust emoji, bad link inside).
4. **Email — forged:** click "Try a fake PayPal email" → **DANGEROUS**
   (SPF/DKIM/DMARC fail, sender does not match its server, fake link).
5. **File — PDF:** upload any PDF → type check, SHA-256, scripts/macros
   scan, hidden links. Try renaming an .exe to `.jpg` — OmniCheck catches
   the lie ("File is lying about what it is").

To turn on the 70+ antivirus check, start the app with your free
VirusTotal key (same key as the Phishing Link Checker):

```bash
VIRUSTOTAL_API_KEY=your-key python3 app.py
```

Without the key the report honestly says "VirusTotal: not set up" and the
score is captioned "risk from built-in checks only — antivirus check not
run".
