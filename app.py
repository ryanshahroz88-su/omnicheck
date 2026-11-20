#!/usr/bin/env python3
"""
OmniCheck — Universal Safety Checker (Python 3, stdlib only).

A DEFENSIVE safety tool. Give it a link, an email, a file, or a pasted
message and it tells you whether it is safe to open, with plain-language
reasons. It only READS what you give it — it never creates phishing pages,
never captures credentials, never runs uploaded files, and never scans ports.

Run:
    python3 app.py
Then open:
    http://127.0.0.1:8000

Modes (tabs in the GUI):
  * Link — everything the Phishing Link Checker did: URL structure tricks
    (@ trick, // trick, punycode/homograph lookalikes, typosquatting vs
    well-known brands, shorteners, IP-address URLs, unusual ports,
    open-redirect parameters, data:/javascript: schemes), redirect chain,
    domain age via RDAP (under 7 days old can never score Safe; under 30
    days old can never score Safe either), DNS A/MX/NS, SPF/DKIM/DMARC,
    SSL/TLS certificate, page content scan (password forms, forms posting
    elsewhere, urgency words), IP-grabber services, and the live threat
    databases (PhishTank verified-online feed — no key needed; Google Safe
    Browsing and VirusTotal — need free API keys).
  * Email — pasted email headers + body: From vs Received chain, SPF /
    DKIM / DMARC results, links inside the email (each one link-checked),
    pressure/scam wording, brand impersonation, risky attachments.
  * File — upload a picture, PDF, Word/Excel/PowerPoint document, zip or
    any file (max 32 MB, never executed — static analysis only): real type
    from magic bytes (flags a renamed file, e.g. an .exe called .jpg),
    SHA-256 hash + VirusTotal hash lookup, PDF scripts/launches/embedded
    files, Office macros and external links, image metadata, zip contents
    (executables, scripts, nested archives), and URLs hidden inside the
    file's text.
  * Text — pasted text, emoji and stickers: scam/phishing wording,
    embedded links (link-checked), hidden Unicode tricks (zero-width
    characters, right-to-left override, look-alike letters) and misleading
    emoji (fake verification/trust symbols). Emojis are plain Unicode and
    cannot run code — only the tricks around them are dangerous. A sticker
    is checked as an image upload (File tab).

Live threat databases: PhishTank verified-online database (no key needed).
Google Safe Browsing and VirusTotal via the environment variables
GOOGLE_SAFE_BROWSING_API_KEY and VIRUSTOTAL_API_KEY — when a key is
absent the report honestly shows "not set up" instead of faking a result.

Honest limits: no tool can prove a link or file 100% safe, and a new
threat can hide from every scanner. A clean result is labelled
"NO KNOWN-BAD FOUND" and means nothing known-bad was found. When the
VirusTotal check did not run, the score is captioned "risk from built-in
checks only — antivirus check not run". If a check could not run, the
report says so instead of inventing a result.

Safety: input is validated, fetches use short timeouts, scripts from a
checked page are never run, uploaded files are never executed, private /
internal IP targets are refused (SSRF protection), and nothing is stored
server-side — history lives in the browser session only.
"""

import base64
import csv
import email
import email.policy
import datetime
import fnmatch
import gzip
import hashlib
import html as html_lib
import html.parser
import io
import ipaddress
import json
import os
import quopri
import random
import re
import socket
import ssl
import struct
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
HOST = "127.0.0.1"
PORT = 8000
UA = "OmniCheck/1.0 (defensive safety-checker tool; +https://github.com/)"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BRANDS = {
    # brand keyword -> official domain
    "paypal": "paypal.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "steam": "steampowered.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "whatsapp": "whatsapp.com",
    "telegram": "telegram.org",
    "youtube": "youtube.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "adobe": "adobe.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "outlook": "outlook.com",
    "hotmail": "hotmail.com",
    "gmail": "gmail.com",
    "yahoo": "yahoo.com",
    "dropbox": "dropbox.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "visa": "visa.com",
    "mastercard": "mastercard.com",
    "stripe": "stripe.com",
    "meta": "meta.com",
    "tiktok": "tiktok.com",
    "spotify": "spotify.com",
    "roblox": "roblox.com",
    "epicgames": "epicgames.com",
    "playstation": "playstation.com",
    "xbox": "xbox.com",
}

# Real domains owned by the brands above (not impersonation — do not flag).
LEGIT_BRAND_DOMAINS = {
    "microsoftonline.com", "live.com", "outlook.com", "hotmail.com",
    "msn.com", "bing.com", "windows.com", "office.com", "sharepoint.com",
    "onedrive.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
    "googlevideo.com", "ggpht.com", "youtu.be", "googlesyndication.com",
    "doubleclick.net", "blogspot.com", "fbcdn.net", "fb.com",
    "messenger.com", "whatsapp.net", "icloud.com", "me.com", "mac.com",
    "amazonaws.com", "cloudfront.net", "nflxvideo.net", "paypalobjects.com",
    "stripe.network", "githubusercontent.com", "licdn.com", "twimg.com",
    "x.com", "t.me", "telegram.me", "spotifycdn.com", "tiktokcdn.com",
    "rbxcdn.com", "steamcommunity.com", "epicgames.dev",
    "sonyentertainmentnetwork.com", "adobedtm.com", "typekit.net",
    "behance.net", "jpmorganchase.com", "amex.com", "americanexpress.com",
    "discover.com", "binance.us", "dropboxusercontent.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "tiny.cc", "rebrand.ly", "bl.ink", "qr.ae", "s.id",
    "short.io", "shrtco.de", "clck.ru", "tr.im", "v.gd", "adf.ly", "bc.vc",
    "soo.gd", "urlz.fr", "gg.gg", "t.ly", "bitly.is", "lnk.to", "shorturl.at",
    "tiny.one", "bit.do", "mcaf.ee", "yourls.org", "shorte.st", "go2l.ink",
    "cutt.us", "u.to", "x.co", "budurl.com", "snip.ly", "snipurl.com",
}

# IP-grabber / tracking-link services: they log the visitor's IP (and more).
TRACKERS = {
    "grabify.link": "Grabify — IP-grabber / tracking link",
    "grabify.com": "Grabify — IP-grabber / tracking link",
    "iplogger.org": "IPLogger — IP-grabber / tracking link",
    "iplogger.com": "IPLogger — IP-grabber / tracking link",
    "iplogger.ru": "IPLogger — IP-grabber / tracking link",
    "iplogger.net": "IPLogger — IP-grabber / tracking link",
    "iplogger.info": "IPLogger — IP-grabber / tracking link",
    "iplog.co": "IPLogger — IP-grabber / tracking link",
    "ip-logger.com": "IPLogger — IP-grabber / tracking link",
    "ipgrabber.com": "IP grabber — tracking link",
    "logger.co": "Tracking-link service",
    "iplogger.io": "IPLogger — IP-grabber / tracking link",
    "grabify.net": "Grabify — IP-grabber / tracking link",
    "iplogger.co": "IPLogger — IP-grabber / tracking link",
    "yip.su": "IP-grabber / tracking link",
    "iplis.ru": "IP-grabber / tracking link",
    "link2you.ru": "Tracking-link service",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "online", "site", "fun", "icu", "buzz", "work",
    "live", "click", "link", "rest", "shop", "ru", "su", "tk", "ml", "ga",
    "cf", "gq", "pw", "cc", "ws", "info", "loan", "men", "date", "faith",
    "review", "stream", "download", "win", "bid", "party", "trade",
    "science", "kim", "monster", "quest", "bar", "casa", "lat", "mom",
    "uno", "zip", "mov", "foo", "dad", "phd", "prof", "esq", "nexus",
    "ing", "meme", "bond", "cyou", "sbs", "lol", "tattoo", "gdn", "ovh",
    "cam", "ooo", "fit", "cfd", "pro", "haus", "art", "skin", "tube",
    "live", "world", "today", "center", "pics", "photo", "pics",
}

OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_to", "redirectto", "next", "return",
    "return_to", "returnto", "continue", "dest", "destination", "target",
    "out", "go", "link", "r", "u", "redir", "forward", "callback",
    "returnurl", "redirect_uri", "relay", "path", "goto", "jump", "to",
    "next_url", "redir_url", "redirecturl", "checkout_url", "login_url",
}

URGENCY_WORDS = [
    "verify now", "verify your account", "account blocked",
    "account suspended", "account will be closed", "act now",
    "immediately", "urgent", "confirm your identity",
    "unusual activity", "security alert", "click here to verify",
    "limited time", "update your payment", "your account has been locked",
    "verify your identity", "suspicious activity detected",
    "action required", "your password expires",
]

# Scam / pressure wording used in fake messages and emails.
SCAM_PHRASES = [
    "you have won", "you won", "congratulations you won", "claim your prize",
    "lottery", "lucky winner", "free iphone", "free gift", "claim now",
    "verify your account", "account will be closed", "account suspended",
    "unusual activity", "confirm your identity", "update your payment",
    "send money", "wire transfer", "western union", "gift card",
    "crypto wallet", "bitcoin", "double your money", "investment opportunity",
    "inheritance", "beneficiary", "bank details", "share your otp",
    "send otp", "your otp", "password expires", "click here to verify",
    "act now", "urgent action required", "limited time offer",
    "your package is held", "customs fee", "delivery failed",
    "tax refund", "irs", "kyc update", "wallet verification",
    "suspended account", "dear customer", "dear beneficiary",
]

# Emoji that scammers use to fake trust (a tick or shield means nothing).
TRUST_EMOJI = {
    "\u2705", "\u2714\ufe0f", "\u2714", "\u2611\ufe0f", "\u2611",
    "\U0001f6e1\ufe0f", "\U0001f6e1", "\U0001f512", "\U0001f525",
    "\u2b50", "\U0001f389", "\u26a0\ufe0f", "\u26a0",
}

# Invisible / direction-changing Unicode characters used to hide tricks.
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u180e"}
BIDI_CHARS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
              "\u2066", "\u2067", "\u2068", "\u2069", "\u061c"}

# File type from magic bytes: (magic bytes, label, usual extensions).
FILE_MAGIC = [
    (b"%PDF", "PDF document", {".pdf"}),
    (b"PK\x03\x04", "ZIP archive", {".zip", ".docx", ".xlsx", ".pptx",
                                   ".jar", ".apk", ".epub"}),
    (b"PK\x05\x06", "ZIP archive (empty)", {".zip", ".docx", ".xlsx",
                                            ".pptx"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"GIF87a", "GIF image", {".gif"}),
    (b"GIF89a", "GIF image", {".gif"}),
    (b"RIFF", "RIFF media (WebP / WAV / AVI)", {".webp", ".wav", ".avi"}),
    (b"MZ", "Windows executable", {".exe", ".dll", ".scr", ".sys"}),
    (b"\x7fELF", "Linux executable", {".elf", ".so", ""}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Old Office document",
     {".doc", ".xls", ".ppt"}),
    (b"Rar!\x1a\x07\x00", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf'\x1c", "7-Zip archive", {".7z"}),
    (b"\x25\x21PS-Adobe-", "PostScript document", {".ps", ".eps"}),
    (b"<?xml", "XML document", {".xml", ".svg"}),
    (b"{\x0c\x00", "Windows shortcut", {".lnk"}),
    (b"\x00\x00\x01\x00", "Icon / cursor file", {".ico", ".cur"}),
]

# Extensions that can run code — dangerous inside an archive or as an
# attachment that pretends to be a picture or document.
DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".ps1", ".psm1", ".jar", ".dll", ".com", ".pif", ".msi", ".hta",
    ".cpl", ".gadget", ".wsf", ".wsh", ".reg", ".sh", ".py", ".apk",
    ".dmg", ".iso", ".img", ".vhd",
}

MAX_FILE_BYTES = 32 * 1024 * 1024  # 32 MB upload limit

# Two-label public suffixes, so "example.co.uk" counts as one registered domain.
TWO_PART_SUFFIXES = {    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "com.mx", "co.in", "com.ar", "com.co",
    "co.za", "com.tr", "co.kr", "com.pl", "com.ru", "co.id", "com.sg",
    "com.hk", "com.tw", "co.il", "com.ph", "com.pk", "com.ng", "com.eg",
    "co.th", "com.vn", "com.my", "co.ke", "com.bd", "github.io",
    "pages.dev", "vercel.app", "netlify.app", "herokuapp.com",
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com",
}

# Cyrillic / Greek / lookalike letters that can impersonate Latin ones.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ʟ": "l",
    "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ᴛ": "t", "ᴜ": "u",
    "ν": "v", "κ": "k", "μ": "u", "ω": "w", "ο": "o", "α": "a", "β": "b",
    "ɑ": "a", "ɒ": "o", "ɛ": "e", "ɨ": "i", "ʉ": "u", "ɵ": "o",
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "þ": "p", "ß": "b",
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e", "ì": "i", "í": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ù": "u",
    "ú": "u", "û": "u", "ü": "u", "ý": "y", "ÿ": "y", "ñ": "n",
    "ç": "c", "ÿ": "y", "0": "o", "1": "l", "5": "s",
}

BLOCKED_HOST_SUFFIXES = (
    ".local", ".lan", ".internal", ".home", ".corp", ".intranet", ".test",
)

OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _levenshtein(a, b):
    """Edit distance between two short strings (for typosquat detection)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]


def _registered_domain(host):
    """Return the registrable domain (e.g. 'sub.example.co.uk' -> 'example.co.uk')."""
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) < 2:
        return host
    suffix = ".".join(parts[-2:])
    if suffix in TWO_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def _deconfuse(host):
    """Map lookalike unicode letters back to Latin (for homograph checks)."""
    return "".join(CONFUSABLES.get(ch, ch) for ch in host)


def _normalize_url(raw):
    """Return a canonical URL string for comparison, or None if unparseable."""
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urllib.parse.urlparse(raw)
    except ValueError:
        return None
    if not p.netloc:
        return None
    host = p.hostname or ""
    if not host:
        return None
    host = host.lower().rstrip(".")
    port = ""
    try:
        if p.port and ((p.scheme == "http" and p.port != 80) or
                       (p.scheme == "https" and p.port != 443)):
            port = ":%d" % p.port
    except ValueError:
        return None
    path = p.path or ""
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    out = "%s://%s%s%s" % (p.scheme.lower(), host, port, path)
    if p.query:
        out += "?" + p.query
    return out


def _ip_is_blocked(ip_str):
    """True if an IP is internal-only (SSRF protection).

    Only truly internal ranges are blocked: RFC1918 private addresses,
    loopback, link-local (incl. the 169.254.169.254 cloud-metadata address),
    multicast and unspecified. CGNAT (100.64/10) and the 198.18/15
    benchmarking range are NOT blocked — some networks and proxies answer
    public DNS with those addresses, and blocking them would make the tool
    refuse every public site behind such a proxy.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip.is_multicast or ip.is_unspecified:
        return True
    for net in _BLOCKED_NETS:
        if ip.version == net.version and ip in net:
            return True
    return False


_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _host_is_blocked(host):
    """True for localhost / internal hostnames that must never be fetched."""
    host = (host or "").lower().strip(".")
    if host in ("localhost", "ip6-localhost", "ip6-loopback"):
        return True
    return any(host.endswith(sfx) for sfx in BLOCKED_HOST_SUFFIXES)


# ---------------------------------------------------------------------------
# Minimal DNS client (stdlib only, UDP) — A / MX / NS / TXT
# ---------------------------------------------------------------------------

def _dns_read_name(msg, off):
    labels = []
    jumped = False
    next_off = off
    seen = set()
    while True:
        if off >= len(msg):
            raise ValueError("bad name")
        ln = msg[off]
        if ln == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if ptr in seen:
                raise ValueError("pointer loop")
            seen.add(ptr)
            if not jumped:
                next_off = off + 2
                jumped = True
            off = ptr
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("utf-8", "replace"))
        off += ln
    return ".".join(labels), next_off


def _system_resolvers():
    out = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    out.append(parts[1])
    except OSError:
        pass
    return out


def _dns_exchange(packet, ns, timeout=4.0):
    """Send one DNS query. UDP first, TCP fallback (RFC 7766).

    Returns the raw response bytes, or None if the resolver is unreachable.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ns, 53))
        data, _ = sock.recvfrom(8192)
        sock.close()
        return data
    except Exception:
        pass
    try:
        sock = socket.create_connection((ns, 53), timeout=timeout)
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        hdr = b""
        while len(hdr) < 2:
            chunk = sock.recv(2 - len(hdr))
            if not chunk:
                raise IOError("short read")
            hdr += chunk
        (ln,) = struct.unpack(">H", hdr)
        data = b""
        while len(data) < ln:
            chunk = sock.recv(min(4096, ln - len(data)))
            if not chunk:
                raise IOError("short read")
            data += chunk
        sock.close()
        return data
    except Exception:
        return None


def _dns_query(name, qtype, timeout=4.0):
    """One DNS question. Returns a list of (rtype, value) answer tuples."""
    qid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("utf-8")
                     for p in name.split(".") if p) + b"\x00"
    packet = header + qname + struct.pack(">HH", qtype, 1)
    resolvers = []
    for ns in ["8.8.8.8", "1.1.1.1"] + _system_resolvers():
        if ns not in resolvers:
            resolvers.append(ns)
    for ns in resolvers:
        data = _dns_exchange(packet, ns, timeout)
        if data is None or len(data) < 12:
            continue
        try:
            rid, _rflags, qd, an, _ns, _ar = struct.unpack(
                ">HHHHHH", data[:12])
        except struct.error:
            continue
        if rid != qid:
            continue
        off = 12
        try:
            for _ in range(qd):
                _, off = _dns_read_name(data, off)
                off += 4
            answers = []
            for _ in range(an):
                _, off = _dns_read_name(data, off)
                rtype, _rclass, _ttl, rdlen = struct.unpack(
                    ">HHIH", data[off:off + 10])
                off += 10
                rdata = data[off:off + rdlen]
                roff = off
                off += rdlen
                if rtype == 1 and rdlen == 4:
                    answers.append(("A", socket.inet_ntoa(rdata)))
                elif rtype == 28 and rdlen == 16:
                    answers.append(("AAAA", str(ipaddress.IPv6Address(rdata))))
                elif rtype == 2:
                    nm, _ = _dns_read_name(data, roff)
                    answers.append(("NS", nm))
                elif rtype == 15 and rdlen >= 3:
                    pref = struct.unpack(">H", rdata[:2])[0]
                    exch, _ = _dns_read_name(data, roff + 2)
                    answers.append(("MX", (pref, exch)))
                elif rtype == 16:
                    txts = []
                    i = 0
                    while i < len(rdata):
                        ln = rdata[i]
                        i += 1
                        txts.append(rdata[i:i + ln].decode("utf-8", "replace"))
                        i += ln
                    answers.append(("TXT", " ".join(txts)))
            return answers
        except Exception:
            continue
    return []


def _doh_query(name, qtype_name):
    """DNS-over-HTTPS fallback via dns.google (works through HTTP proxies).

    Used only when the normal UDP/TCP DNS query returns nothing — e.g. on
    networks where direct DNS is blocked. Returns (rtype, value) tuples.
    """
    try:
        url = ("https://dns.google/resolve?name=%s&type=%s"
               % (urllib.parse.quote(name), qtype_name))
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        out = []
        for ans in data.get("Answer", []):
            t = ans.get("type")
            d = (ans.get("data") or "").strip()
            if t == 1:
                out.append(("A", d))
            elif t == 2:
                out.append(("NS", d.rstrip(".")))
            elif t == 15:
                parts = d.split()
                if len(parts) >= 2:
                    try:
                        out.append(("MX", (int(parts[0]),
                                           parts[1].rstrip("."))))
                    except ValueError:
                        pass
            elif t == 16:
                out.append(("TXT", d.strip('"')))
        return out
    except Exception:
        return []


def dns_lookup(domain):
    """Return {'A': [...], 'MX': [...], 'NS': [...], 'TXT': [...]}."""
    out = {"A": [], "MX": [], "NS": [], "TXT": []}
    for qtype, key in ((1, "A"), (15, "MX"), (2, "NS"), (16, "TXT")):
        try:
            for rtype, value in _dns_query(domain, qtype):
                if rtype in out and value not in out[rtype]:
                    out[rtype].append(value)
        except Exception:
            pass
        if not out[key]:
            # Direct DNS is blocked on some networks — try DNS-over-HTTPS.
            for rtype, value in _doh_query(domain, key):
                if rtype in out and value not in out[rtype]:
                    out[rtype].append(value)
    if not out["A"]:
        # Fallback: the operating system's own resolver.
        try:
            for _fam, _typ, _proto, _canon, sockaddr in socket.getaddrinfo(
                    domain, 443, 0, socket.SOCK_STREAM):
                ip = sockaddr[0]
                if ip not in out["A"]:
                    out["A"].append(ip)
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Fetching (short timeouts, size caps, never executes anything)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib from following redirects automatically (we walk them)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_get(url, timeout=8.0, max_bytes=262144):
    """GET a URL. Returns (status, headers_dict, body_bytes)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            body = body[:max_bytes]
        if headers.get("content-encoding") == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        return resp.status, headers, body


def follow_redirects(url, max_hops=10):
    """Walk the redirect chain manually.

    Returns (chain, final_url, error) where chain is a list of
    {'url': ..., 'status': ...} for every hop.
    """
    chain = []
    current = url
    seen = set()
    for _ in range(max_hops):
        if current in seen:
            return chain, current, "redirect loop"
        seen.add(current)
        try:
            status, headers, _body = _http_get(current, timeout=8.0,
                                               max_bytes=1024)
        except urllib.error.HTTPError as e:
            status = e.code
            headers = {k.lower(): v for k, v in e.headers.items()}
            if status in (301, 302, 303, 307, 308):
                loc = headers.get("location")
                if not loc:
                    return chain, current, "redirect without location"
                chain.append({"url": current, "status": status})
                current = urllib.parse.urljoin(current, loc)
                continue
            chain.append({"url": current, "status": status})
            return chain, current, None
        except Exception as e:
            return chain, current, "fetch failed: %s" % _short_err(e)
        chain.append({"url": current, "status": status})
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location")
            if not loc:
                return chain, current, "redirect without location"
            current = urllib.parse.urljoin(current, loc)
            continue
        return chain, current, None
    return chain, current, "too many redirects"


def _short_err(exc):
    msg = str(exc)
    if len(msg) > 120:
        msg = msg[:120] + "..."
    return msg or exc.__class__.__name__


# ---------------------------------------------------------------------------
# RDAP — domain age
# ---------------------------------------------------------------------------

def rdap_age(domain):
    """Return (creation_date_iso, age_days) or (None, None) if unknown."""
    try:
        req = urllib.request.Request(
            "https://rdap.org/domain/" + domain,
            headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                raw = ev.get("eventDate", "")
                try:
                    dt = datetime.datetime.fromisoformat(
                        raw.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                age = (datetime.datetime.now(datetime.timezone.utc)
                       - dt).days
                return dt.date().isoformat(), max(age, 0)
    except Exception:
        pass
    return None, None


# ---------------------------------------------------------------------------
# SSL / TLS certificate
# ---------------------------------------------------------------------------

def _parse_cert_time(value):
    # e.g. 'Nov 15 12:00:00 2026 GMT'
    dt = datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=datetime.timezone.utc)


def _cert_matches_host(cert, host):
    host = host.lower()
    names = []
    for typ, val in cert.get("subjectAltName", []):
        if typ == "DNS":
            names.append(val.lower())
    if not names:
        for rdn in cert.get("subject", []):
            for key, val in rdn:
                if key == "commonName":
                    names.append(val.lower())
    for name in names:
        if name == host:
            return True
        if name.startswith("*.") and fnmatch.fnmatch(host, name):
            return True
    return False


def ssl_info(host, timeout=6.0):
    """Return a dict about the site's certificate, or {'error': ...}."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        # Retry without verification so we can still describe the bad cert.
        reason = str(e).lower()
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
        except Exception as e2:
            return {"error": _short_err(e2)}
        info = _cert_dict(cert, host)
        if "expired" in reason:
            info["problem"] = "expired"
        elif "self-signed" in reason or "self signed" in reason:
            info["problem"] = "self-signed"
        else:
            info["problem"] = "untrusted"
        return info
    except Exception as e:
        return {"error": _short_err(e)}
    info = _cert_dict(cert, host)
    if not _cert_matches_host(cert, host):
        info["problem"] = "mismatched"
    return info


def _cert_dict(cert, host):
    issuer = {}
    for rdn in cert.get("issuer", []):
        for key, val in rdn:
            issuer[key] = val
    issuer_name = issuer.get("organizationName") or issuer.get("commonName") \
        or "unknown issuer"
    expires = None
    days_left = None
    try:
        exp = _parse_cert_time(cert["notAfter"])
        expires = exp.date().isoformat()
        days_left = (exp - datetime.datetime.now(datetime.timezone.utc)).days
    except Exception:
        pass
    return {
        "issuer": issuer_name,
        "expires": expires,
        "days_left": days_left,
        "matches_host": _cert_matches_host(cert, host),
    }


# ---------------------------------------------------------------------------
# Page content (parsed, never executed)
# ---------------------------------------------------------------------------

class _PageParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._cur = None
        self.favicon = None
        self.title = ""
        self._in_title = False
        self.text_parts = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._cur = {"action": d.get("action", ""), "password": False}
        elif tag == "input" and self._cur is not None:
            if d.get("type", "").lower() == "password":
                self._cur["password"] = True
        elif tag == "link":
            rel = d.get("rel", "").lower()
            if "icon" in rel and d.get("href"):
                self.favicon = d["href"]
        elif tag == "title":
            self._in_title = True
        elif tag == "a" and d.get("href"):
            self.links.append(d["href"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if data.strip():
            self.text_parts.append(data)


def fetch_page(url, timeout=8.0):
    """Fetch and parse a page. Returns a dict (never raises)."""
    try:
        status, _headers, body = _http_get(url, timeout=timeout,
                                           max_bytes=262144)
    except urllib.error.HTTPError as e:
        return {"error": "page returned HTTP %d" % e.code}
    except Exception as e:
        return {"error": _short_err(e)}
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        text = ""
    parser = _PageParser()
    try:
        parser.feed(text[:200000])
    except Exception:
        pass
    return {
        "status": status,
        "title": parser.title.strip()[:200],
        "forms": parser.forms,
        "favicon": parser.favicon,
        "text": " ".join(parser.text_parts)[:20000],
        "links": parser.links[:200],
    }


# ---------------------------------------------------------------------------
# Live threat databases
# ---------------------------------------------------------------------------

_FEED_CACHE = {
    "openphish": {"at": 0.0, "urls": set(), "domains": set(), "ok": False},
    "phishtank": {"at": 0.0, "urls": set(), "domains": set(), "ok": False},
}
_FEED_LOCK = threading.Lock()


def _feed_get(name, ttl_seconds):
    with _FEED_LOCK:
        entry = _FEED_CACHE[name]
        if entry["ok"] and time.time() - entry["at"] < ttl_seconds:
            return entry
        if time.time() - entry["at"] < 60 and entry["ok"]:
            return entry  # do not hammer a just-failed feed
        entry["at"] = time.time()
    urls, domains = set(), set()
    ok = False
    try:
        if name == "openphish":
            req = urllib.request.Request(OPENPHISH_URL,
                                         headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read(4 * 1024 * 1024).decode("utf-8", "replace")
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                urls.add(line.lower())
                try:
                    host = urllib.parse.urlparse(line).hostname
                    if host:
                        domains.add(host.lower())
                except ValueError:
                    pass
            ok = True
        else:  # phishtank (retry: the CDN sometimes answers 404)
            raw = None
            last_err = None
            for _attempt in range(3):
                try:
                    req = urllib.request.Request(PHISHTANK_URL,
                                                 headers={"User-Agent": UA})
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        raw = gzip.decompress(resp.read(16 * 1024 * 1024))
                    break
                except Exception as e:  # noqa: BLE001 - retried below
                    last_err = e
                    time.sleep(1)
            if raw is None:
                raise last_err
            text = raw.decode("utf-8", "replace")
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                if (row.get("online") or "").strip().lower() != "yes":
                    continue
                u = (row.get("url") or "").strip()
                if not u:
                    continue
                urls.add(u.lower())
                try:
                    host = urllib.parse.urlparse(u).hostname
                    if host:
                        domains.add(host.lower())
                except ValueError:
                    pass
            ok = True
    except Exception:
        ok = False
    with _FEED_LOCK:
        entry = _FEED_CACHE[name]
        if ok:
            entry.update({"urls": urls, "domains": domains, "ok": True,
                          "at": time.time()})
        else:
            entry["ok"] = entry.get("ok", False)
        return entry


# Domains so big and trusted that a few listed pages on them do not make
# the whole domain phishing (e.g. google.com hosts phishing pages on its
# own services). For these, only an exact-URL listing counts — a
# domain-level hit is ignored.
_TRUSTED_FEED_DOMAINS = set(BRANDS.values()) | LEGIT_BRAND_DOMAINS


def feed_lookup(name, url, host, reg_domain):
    """Check one URL against a cached feed.

    Returns ('exact'|'domain'|'none'|'unavailable', detail).
    """
    ttl = 1800 if name == "openphish" else 21600
    entry = _feed_get(name, ttl)
    if not entry["ok"]:
        return "unavailable", "feed could not be reached"
    norm = _normalize_url(url) or url.lower()
    if norm.lower() in entry["urls"]:
        return "exact", "exact URL is listed"
    if host and host.lower() in entry["domains"]:
        h = host.lower()
        bare = h[4:] if h.startswith("www.") else h
        if bare in _TRUSTED_FEED_DOMAINS:
            # A few listed pages on a trusted host (google.com, etc.) do
            # not make the host itself phishing — the exact-URL check
            # above already catches a truly listed page.
            pass
        else:
            return "domain", "another page on this exact host is listed"
    if reg_domain and reg_domain in entry["domains"]:
        if reg_domain in _TRUSTED_FEED_DOMAINS:
            return "none", "not listed"
        return "domain", "another page on this domain is listed"
    return "none", "not listed"


def gsb_check(url):
    """Google Safe Browsing Lookup API. Returns a status dict."""
    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not key:
        return {"status": "not_set_up"}
    body = json.dumps({
        "client": {"clientId": "phishing-link-checker",
                   "clientVersion": VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            GSB_URL + "?key=" + urllib.parse.quote(key),
            data=body, headers={"Content-Type": "application/json",
                                "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"status": "error", "detail": "HTTP %d" % e.code}
    except Exception as e:
        return {"status": "error", "detail": _short_err(e)}
    matches = data.get("matches") or []
    if matches:
        kinds = sorted({m.get("threatType", "?") for m in matches})
        return {"status": "listed", "detail": ", ".join(kinds)}
    return {"status": "clear"}


def virustotal_check(url):
    """VirusTotal URL report. Returns a status dict."""
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"status": "not_set_up"}
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    url_id = url_id.rstrip("=")
    try:
        req = urllib.request.Request(
            "https://www.virustotal.com/api/v3/urls/" + url_id,
            headers={"x-apikey": key, "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "unknown",
                    "detail": "not in the VirusTotal database"}
        return {"status": "error", "detail": "HTTP %d" % e.code}
    except Exception as e:
        return {"status": "error", "detail": _short_err(e)}
    stats = (data.get("data", {}).get("attributes", {})
             .get("last_analysis_stats", {}))
    mal = int(stats.get("malicious", 0) or 0)
    sus = int(stats.get("suspicious", 0) or 0)
    return {"status": "done", "malicious": mal, "suspicious": sus}


def virustotal_hash_check(sha256):
    """VirusTotal file report by SHA-256 hash. Returns a status dict."""
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"status": "not_set_up"}
    try:
        req = urllib.request.Request(
            "https://www.virustotal.com/api/v3/files/" + sha256,
            headers={"x-apikey": key, "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "unknown",
                    "detail": "not in the VirusTotal database"}
        return {"status": "error", "detail": "HTTP %d" % e.code}
    except Exception as e:
        return {"status": "error", "detail": _short_err(e)}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal = int(stats.get("malicious", 0) or 0)
    sus = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())
    name = attrs.get("meaningful_name") or attrs.get("type_description") or ""
    return {"status": "done", "malicious": mal, "suspicious": sus,
            "total": total, "name": name}


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

def _finding(findings, level, points, title, detail):
    findings.append({"level": level, "points": points,
                     "title": title, "detail": detail})


def analyze_url(raw_url):
    """Analyse one link. Returns a full report dict (never raises)."""
    started = time.time()
    findings = []
    facts = {"checked_at": datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds") + "Z"}
    raw = (raw_url or "").strip()
    if not raw:
        return {"error": "Please paste a link first."}
    if len(raw) > 2048:
        return {"error": "That link is too long to check (over 2048 characters)."}

    lower = raw.lower()
    if lower.startswith("data:") or lower.startswith("javascript:"):
        _finding(findings, "danger", 90, "Dangerous link type",
                 "This is a data: or javascript: link — it runs code instead "
                 "of opening a normal web page. Never click it.")
        return _finish_report(raw, raw, findings, facts, started)
    if lower.startswith("file:"):
        _finding(findings, "danger", 80, "Local file link",
                 "This link points to a file on a computer, not a website. "
                 "Do not open it.")
        return _finish_report(raw, raw, findings, facts, started)

    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except ValueError:
        return {"error": "That does not look like a valid link."}
    if parsed.scheme not in ("http", "https"):
        return {"error": "Only http:// and https:// links can be checked."}
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return {"error": "That link has no website address in it."}
    reg_domain = _registered_domain(host)
    facts["domain"] = reg_domain
    facts["host"] = host
    url = _normalize_url(raw) or raw

    # --- SSRF protection: refuse private / internal targets -------------
    if _host_is_blocked(host):
        return {"error": "That address is private or internal (localhost / "
                         "local network). This tool only checks public links."}
    try:
        ip = ipaddress.ip_address(host)
        if _ip_is_blocked(str(ip)):
            return {"error": "That IP address is private or reserved. "
                             "This tool only checks public links."}
        facts["ip_literal"] = True
    except ValueError:
        pass  # hostname, not an IP literal

    # --- 1. URL structure -------------------------------------------------
    _check_structure(url, parsed, host, reg_domain, findings)

    # Resolve early: if the host does not resolve, most later checks are moot.
    # A records are for the exact host; MX / NS / TXT (and SPF / DKIM /
    # DMARC) live on the registered domain, not on "www." — check both.
    dns = dns_lookup(host)
    if reg_domain != host:
        dns_reg = dns_lookup(reg_domain)
        for key in ("MX", "NS", "TXT", "A"):
            for value in dns_reg.get(key, []):
                if value not in dns[key]:
                    dns[key].append(value)
    facts["dns"] = dns
    resolved_ips = list(dns.get("A", []))
    blocked_ip = None
    for ip in resolved_ips:
        if _ip_is_blocked(ip):
            blocked_ip = ip
            break
    if blocked_ip:
        return {"error": "That website resolves to a private/internal IP "
                         "(%s). This tool only checks public links."
                         % blocked_ip}
    if not resolved_ips:
        _finding(findings, "warning", 40, "Website does not resolve",
                 "The domain has no DNS address, so the site cannot load. "
                 "Real websites always resolve — dead or fake domains often "
                 "do not.")
    if dns.get("MX"):
        _finding(findings, "pass", 0, "Mail servers found",
                 "The domain has %d mail server(s) — a real organisation "
                 "usually does." % len(dns["MX"]))
    else:
        _finding(findings, "info", 0, "No mail servers (MX)",
                 "This domain has no MX record, so it cannot receive email. "
                 "Many small sites are like this, so it is only a small hint.")
    if dns.get("NS"):
        _finding(findings, "pass", 0, "Name servers found",
                 "%s" % ", ".join(dns["NS"][:3]))
    txt_joined = " ".join(dns.get("TXT", [])).lower()
    spf = "v=spf1" in txt_joined
    dmarc = "v=dmarc1" in txt_joined
    if not dmarc:
        # DMARC lives at _dmarc.<domain>, not on the bare domain.
        dmarc_txt = dns_lookup("_dmarc." + reg_domain).get("TXT", [])
        dmarc = any("v=dmarc1" in t.lower() for t in dmarc_txt)
    dkim = "v=dkim1" in txt_joined or "dkim" in txt_joined
    facts["spf"] = spf
    facts["dmarc"] = dmarc
    facts["dkim"] = dkim
    if spf and dmarc:
        _finding(findings, "pass", 0, "Email authentication set up",
                 "SPF and DMARC are present — the domain owner set up "
                 "email checks. Phishers usually do not bother.")
    elif not spf and not dmarc:
        _finding(findings, "info", 0, "No email authentication (SPF/DMARC)",
                 "The domain has no SPF or DMARC records. On its own this "
                 "means little, but real companies usually set these up.")

    # --- 2. Redirect chain ------------------------------------------------
    final_url = url
    chain_error = None
    if parsed.scheme in ("http", "https"):
        chain, final_url, chain_error = follow_redirects(url)
        facts["redirects"] = chain
        facts["final_url"] = final_url
        if chain_error:
            _finding(findings, "info", 0, "Redirect check incomplete",
                     chain_error + " — the redirect result may be partial.")
        if len(chain) > 1:
            hops = len(chain) - 1
            final_host = (urllib.parse.urlparse(final_url).hostname or "")
            final_host = final_host.lower().rstrip(".")
            if final_host and final_host != host:
                _finding(findings, "warning", 20,
                         "Link ends up on a different website",
                         "You typed %s but the link finally opens %s. "
                         "A different final website is a classic phishing "
                         "trick." % (host, final_host))
            else:
                _finding(findings, "info", 0, "Redirects: %d hop(s)" % hops,
                         "The link redirects, but ends on the same website.")
            if hops >= 3:
                _finding(findings, "warning", 10, "Many redirects (%d)" % hops,
                         "Lots of hops are used to hide where a link really "
                         "goes.")
    try:
        final_host = (urllib.parse.urlparse(final_url).hostname or "").lower()
    except ValueError:
        final_host = host

    # --- 3. Domain age (RDAP) ---------------------------------------------
    created, age_days = rdap_age(reg_domain)
    facts["domain_created"] = created
    facts["domain_age_days"] = age_days
    age_floor = 0
    if age_days is None:
        _finding(findings, "info", 0, "Domain age could not be checked",
                 "The domain's creation date was not available, so this "
                 "check was skipped — not a pass, just unknown.")
    else:
        if age_days < 7:
            age_floor = 55
            _finding(findings, "danger", 40,
                     "Domain is only %d day(s) old" % age_days,
                     "Created on %s. Real official websites use old domains "
                     "— a brand-new domain with a perfect-looking page is a "
                     "classic phishing trick." % created)
        elif age_days < 30:
            age_floor = 40
            _finding(findings, "warning", 25,
                     "Domain is only %d days old" % age_days,
                     "Created on %s. A website less than a month old is "
                     "suspicious, even if everything else looks fine."
                     % created)
        elif age_days < 365:
            _finding(findings, "info", 0,
                     "Domain is %d days old" % age_days,
                     "Created on %s — fairly new, but not brand-new."
                     % created)
        else:
            _finding(findings, "pass", 0,
                     "Domain is %d days old" % age_days,
                     "Created on %s — an established domain." % created)

    # --- 4. SSL / TLS (only for https) ------------------------------------
    if parsed.scheme == "https" and resolved_ips:
        cert = ssl_info(final_host or host)
        facts["certificate"] = cert
        if "error" in cert:
            _finding(findings, "info", 0, "Certificate could not be checked",
                     cert["error"] + " — skipped, not a pass.")
        else:
            problem = cert.get("problem")
            if problem == "expired":
                _finding(findings, "danger", 50, "SSL certificate expired",
                         "Expired on %s. Browsers block expired certificates "
                         "— a real site keeps its certificate current."
                         % cert.get("expires"))
            elif problem == "self-signed":
                _finding(findings, "danger", 45,
                         "Self-signed SSL certificate",
                         "The certificate was made by the site itself, not "
                         "by a trusted authority. Real sites use trusted "
                         "certificates.")
            elif problem == "mismatched":
                _finding(findings, "danger", 50,
                         "Certificate is for a different website",
                         "The certificate does not match this domain — a "
                         "strong sign the page is impersonating someone.")
            elif problem == "untrusted":
                _finding(findings, "warning", 35,
                         "SSL certificate is not trusted",
                         "The certificate is not from a trusted authority.")
            else:
                days_left = cert.get("days_left")
                if days_left is not None and days_left < 30:
                    _finding(findings, "info", 0,
                             "Certificate expires soon (%d days)" % days_left,
                             "Issued by %s, expires %s."
                             % (cert.get("issuer"), cert.get("expires")))
                else:
                    _finding(findings, "pass", 0,
                             "SSL certificate is valid",
                             "Issued by %s, expires %s."
                             % (cert.get("issuer"), cert.get("expires")))

    # --- 5. Page content ---------------------------------------------------
    page = None
    if parsed.scheme in ("http", "https") and resolved_ips:
        page = fetch_page(final_url)
        if "error" in page:
            _finding(findings, "info", 0, "Page content could not be read",
                     page["error"] + " — skipped, not a pass.")
        else:
            _check_content(page, host, reg_domain, final_url, findings)

    # --- 6. Live threat databases ------------------------------------------
    vt_status = _check_feeds(url, host, reg_domain, findings)
    facts["vt_ran"] = (vt_status == "done")

    # --- 7. Telegram note ---------------------------------------------------
    if host in ("t.me", "telegram.me") or host.endswith(".t.me"):
        _finding(findings, "info", 10,
                 "Telegram link — bot cannot be verified",
                 "This link opens Telegram. A link checker cannot see what "
                 "a bot does inside Telegram, so never share OTPs, "
                 "passwords or payment details with a bot.")

    return _finish_report(url, final_url, findings, facts, started,
                          age_floor=age_floor)


def _check_structure(url, parsed, host, reg_domain, findings):
    """URL-structure tricks (no network needed)."""
    scheme = parsed.scheme.lower()

    if scheme == "http":
        _finding(findings, "warning", 15, "No encryption (http, not https)",
                 "The link uses plain http, so anything typed on the page "
                 "could be read by others.")

    # @ trick: https://real.com@fake.com/ — the real host is after the @.
    if "@" in (parsed.netloc or ""):
        _finding(findings, "danger", 30, "@ trick in the link",
                 "Everything before the @ is fake — the real website is "
                 "after the @, and it is %s." % host)

    # // redirect trick inside the path.
    if "//" in (parsed.path or ""):
        _finding(findings, "warning", 25, "// trick in the link",
                 "A second // inside the link can send you to a different "
                 "website than the one you think you are opening.")

    # IP-address URL.
    try:
        ipaddress.ip_address(host)
        _finding(findings, "warning", 40, "Link uses an IP address, not a name",
                 "Real websites use a name like example.com. Phishing links "
                 "often hide behind a bare IP address.")
    except ValueError:
        pass

    # Punycode / homograph.
    if "xn--" in host:
        _finding(findings, "danger", 35, "Punycode domain (lookalike letters)",
                 "The domain uses encoded characters that can look like "
                 "normal letters — a common way to fake a famous name.")
    elif any(ord(ch) > 127 for ch in host):
        mapped = _deconfuse(host)
        _finding(findings, "warning", 35, "Non-English letters in the domain",
                 "The domain contains unusual letters that can look like "
                 "normal ones (%s). Treat it as suspicious." % mapped)

    # Brand impersonation / typosquatting.
    _check_brand(host, reg_domain, findings)

    # Shorteners and trackers.
    if host in SHORTENERS or reg_domain in SHORTENERS:
        _finding(findings, "warning", 15, "Shortened link",
                 "The real destination is hidden behind a short link. "
                 "This tool follows it and shows where it really goes.")
    if host in TRACKERS or reg_domain in TRACKERS:
        _finding(findings, "danger", 45,
                 "IP-grabber / tracking link (%s)" % (TRACKERS.get(host) or
                                                       TRACKERS.get(reg_domain)),
                 "This service logs the visitor's IP address and device "
                 "details. Do not open it unless you know who sent it.")
    elif "grabify" in host or "iplogger" in host or "iplogger" in reg_domain:
        _finding(findings, "danger", 45, "IP-grabber / tracking link",
                 "This looks like an IP-logging service — it records who "
                 "clicks it. Do not open it.")

    # Unusual port.
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        _finding(findings, "info", 10, "Unusual port (%d)" % port,
                 "Normal websites use port 80 or 443. An odd port is a "
                 "small hint that something is off.")

    # Open-redirect parameters.
    try:
        params = urllib.parse.parse_qsl(parsed.query or "", keep_blank_values=True)
    except ValueError:
        params = []
    for key, value in params:
        if key.lower() in OPEN_REDIRECT_PARAMS:
            v = value.strip().lower()
            if v.startswith("http://") or v.startswith("https://") \
                    or v.startswith("//"):
                _finding(findings, "warning", 30,
                         "Open-redirect parameter (%s)" % key,
                         "The link carries another website address inside "
                         "it — clicking can bounce you to a different site.")
                break

    # Excessive subdomains.
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 5:
        _finding(findings, "warning", 15,
                 "Too many subdomains (%d parts)" % len(labels),
                 "A long chain of subdomains is often used to bury the "
                 "real domain name at the end.")
    elif len(labels) == 4:
        _finding(findings, "info", 0, "Several subdomains",
                 "The address has extra parts before the real domain — "
                 "check that the last two parts are the real website.")

    # Suspicious TLD.
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        _finding(findings, "warning", 15,
                 "Suspicious ending (.%s)" % tld,
                 "This domain ending is used by phishing pages far more "
                 "often than by real companies.")

    # Very long / obfuscated URL.
    if len(url) > 200:
        _finding(findings, "info", 10, "Very long link (%d characters)" % len(url),
                 "Long links are often used to hide the suspicious part "
                 "far to the right.")
    if url.count("%") >= 5:
        _finding(findings, "warning", 15, "Heavily encoded link",
                 "Lots of % codes hide what the link really says.")

    # Lookalike of a well-known domain via the path (e.g. paypal.com@...).
    # (Host-level brand check already covers the main cases.)


def _check_brand(host, reg_domain, findings):
    """Typosquatting / lookalike detection vs well-known brands."""
    if reg_domain in LEGIT_BRAND_DOMAINS:
        return  # a real domain owned by a brand — not impersonation
    label = reg_domain.split(".")[0]
    for brand, official in BRANDS.items():
        if reg_domain == official:
            return  # it IS the official domain — nothing to flag
        # Exact brand word with extra characters, e.g. paypal-secure.com
        if brand in label and label != brand:
            _finding(findings, "danger", 45,
                     "Looks like %s, but is not %s" % (official, official),
                     "The domain contains the name %s yet is not the real "
                     "%s. This is the classic fake-login trick."
                     % (brand, official))
            return
        # Deconfused lookalike (Cyrillic etc. mapped back to Latin).
        mapped = _deconfuse(label)
        if mapped == brand and label != brand:
            _finding(findings, "danger", 45,
                     "Lookalike of %s using foreign letters" % official,
                     "The name looks like %s but uses lookalike characters "
                     "— it is not the real site." % official)
            return
        # Small typo: paypa1, g00gle, faceb00k, micros0ft...
        if len(brand) >= 4 and _levenshtein(label, brand) in (1, 2) \
                and len(label) >= 4:
            _finding(findings, "danger", 45,
                     "Possible typo of %s" % official,
                     "'%s' is one or two letters away from %s. Typo domains "
                     "are a classic phishing trick." % (reg_domain, official))
            return


def _check_content(page, host, reg_domain, final_url, findings):
    """Analyse the fetched page (HTML is parsed, never executed)."""
    text_low = (page.get("text") or "").lower()
    title_low = (page.get("title") or "").lower()

    for form in page.get("forms", []):
        action = (form.get("action") or "").strip()
        action_host = ""
        if action:
            try:
                action_host = (urllib.parse.urlparse(
                    urllib.parse.urljoin(final_url, action)).hostname or "")
            except ValueError:
                action_host = ""
        if form.get("password"):
            _finding(findings, "danger", 35, "Page asks for a password",
                     "The page has a password field. A link that leads to "
                     "a login form deserves extra care — check the domain "
                     "before typing anything.")
            if action_host and action_host.lower().rstrip(".") != host:
                _finding(findings, "danger", 30,
                         "Password goes to a different website",
                         "The login form sends your password to %s, not to "
                         "%s. That is how credentials are stolen."
                         % (action_host, host))
            break
    else:
        if page.get("forms"):
            _finding(findings, "info", 0, "Page has a form",
                     "The page contains a form, but no password field.")

    found_words = [w for w in URGENCY_WORDS if w in text_low]
    if found_words:
        _finding(findings, "warning", 15, "Pressure words on the page",
                 "The page says things like '%s' — scammers use urgency "
                 "to rush you into clicking." % found_words[0])

    # Brand mentioned in the text/title, but the domain is not that brand.
    for brand, official in BRANDS.items():
        if brand in text_low or brand in title_low:
            if reg_domain != official and reg_domain not in LEGIT_BRAND_DOMAINS:
                _finding(findings, "danger", 40,
                         "Page pretends to be %s" % official,
                         "The page talks about %s, but the real domain is "
                         "%s — not %s. That is impersonation."
                         % (brand, reg_domain, official))
            break

    # Favicon hosted on a different domain.
    fav = page.get("favicon")
    if fav:
        try:
            fav_host = (urllib.parse.urlparse(
                urllib.parse.urljoin(final_url, fav)).hostname or "").lower()
            if fav_host and fav_host != host \
                    and _registered_domain(fav_host) != reg_domain:
                _finding(findings, "info", 10,
                         "Page icon comes from another website",
                         "The favicon is loaded from %s instead of this "
                         "site — a small sign the page may be copied."
                         % fav_host)
        except ValueError:
            pass


def _check_feeds(url, host, reg_domain, findings):
    """OpenPhish, PhishTank, Google Safe Browsing, VirusTotal."""
    for name, label in (("openphish", "OpenPhish"),
                        ("phishtank", "PhishTank")):
        kind, detail = feed_lookup(name, url, host, reg_domain)
        if kind == "exact":
            _finding(findings, "danger", 100,
                     "Listed as verified phishing (%s)" % label,
                     "This exact link is in the live %s database of "
                     "confirmed phishing pages. Do not open it." % label)
        elif kind == "domain":
            _finding(findings, "danger", 60,
                     "Domain listed in %s database" % label,
                     "Other pages on this exact domain are in the live %s "
                     "database of confirmed phishing pages." % label)
        elif kind == "unavailable":
            _finding(findings, "info", 0,
                     "%s check unavailable" % label,
                     "The %s database could not be reached this time — "
                     "skipped, not a pass." % label)
        else:
            _finding(findings, "pass", 0, "Not in the %s database" % label,
                     "Checked against the live %s feed — not listed." % label)

    gsb = gsb_check(url)
    if gsb["status"] == "not_set_up":
        _finding(findings, "info", 0, "Google Safe Browsing: not set up",
                 "Add a free API key in the settings (environment variable "
                 "GOOGLE_SAFE_BROWSING_API_KEY) to turn this check on.")
    elif gsb["status"] == "listed":
        _finding(findings, "danger", 100,
                 "Flagged by Google Safe Browsing",
                 "Google lists this link as %s." % gsb.get("detail", "unsafe"))
    elif gsb["status"] == "error":
        _finding(findings, "info", 0, "Google Safe Browsing: check failed",
                 gsb.get("detail", "error") + " — skipped, not a pass.")
    else:
        _finding(findings, "pass", 0, "Google Safe Browsing: clear",
                 "Google's Safe Browsing list does not flag this link.")

    vt = virustotal_check(url)
    vt_status = vt["status"]
    if vt["status"] == "not_set_up":
        _finding(findings, "info", 0, "VirusTotal: not set up",
                 "Add a free API key (environment variable "
                 "VIRUSTOTAL_API_KEY) to turn this check on.")
    elif vt["status"] == "unknown":
        _finding(findings, "info", 0, "VirusTotal: not in database",
                 "VirusTotal has never seen this link before — no verdict "
                 "from its engines yet.")
    elif vt["status"] == "error":
        _finding(findings, "info", 0, "VirusTotal: check failed",
                 vt.get("detail", "error") + " — skipped, not a pass.")
    else:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal >= 3:
            _finding(findings, "danger", 90,
                     "VirusTotal: %d engines call it malicious" % mal,
                     "%d security engines flag this link as malicious and "
                     "%d as suspicious." % (mal, sus))
        elif mal >= 1:
            _finding(findings, "danger", 50,
                     "VirusTotal: %d engine(s) call it malicious" % mal,
                     "At least one security engine flags this link.")
        elif sus > 0:
            _finding(findings, "warning", 25,
                     "VirusTotal: %d engine(s) call it suspicious" % sus,
                     "No engine calls it malicious, but some find it "
                     "suspicious.")
        else:
            _finding(findings, "pass", 0, "VirusTotal: clean",
                     "No VirusTotal engine flags this link.")
    return vt_status


def _finish_report(url, final_url, findings, facts, started, age_floor=0):
    """Score the findings and build the final report dict."""
    score = sum(f.get("points", 0) for f in findings)
    score = max(0, min(100, score))
    if age_floor and score < age_floor:
        score = age_floor
    if score <= 10:
        verdict = "Safe to open"
        verdict_key = "safe"
        verdict_sub = "Yes — this link looks safe to open."
    elif score <= 49:
        verdict = "Open with caution"
        verdict_key = "caution"
        verdict_sub = ("Careful — this link has warning signs. Read the "
                       "findings below before you open it.")
    else:
        verdict = "Do NOT open"
        verdict_key = "dangerous"
        verdict_sub = ("No — do not open this link. It shows strong signs "
                       "of phishing or tracking.")
    facts["final_url"] = final_url or url
    facts["duration_seconds"] = round(time.time() - started, 1)
    vt_ran = bool(facts.get("vt_ran"))
    display = [["Website", facts.get("domain") or "—"],
               ["Domain created",
                (facts.get("domain_created") or "unknown")
                + ((" (%d days old)" % facts["domain_age_days"])
                   if facts.get("domain_age_days") is not None else "")]]
    dns = facts.get("dns") or {}
    if dns:
        display.append(["DNS — A records", ", ".join(dns.get("A") or [])
                        or "none"])
        display.append(["DNS — MX (mail)",
                        ", ".join(m[1] for m in (dns.get("MX") or []))
                        or "none"])
        display.append(["DNS — NS", ", ".join(dns.get("NS") or []) or "none"])
        display.append(["Email checks",
                        "SPF: %s · DMARC: %s · DKIM: %s" % (
                            "yes" if facts.get("spf") else "no",
                            "yes" if facts.get("dmarc") else "no",
                            "yes" if facts.get("dkim") else "no")])
    cert = facts.get("certificate") or {}
    if cert and not cert.get("error"):
        display.append(["Certificate",
                        "%s · expires %s%s" % (
                            cert.get("issuer", "?"),
                            cert.get("expires") or "?",
                            (" (%d days left)" % cert["days_left"])
                            if cert.get("days_left") is not None else "")])
    return {
        "url": url,
        "label": url,
        "mode": "link",
        "final_url": final_url or url,
        "domain": facts.get("domain"),
        "score": score,
        "verdict": verdict,
        "verdict_key": verdict_key,
        "verdict_sub": verdict_sub,
        "vt_ran": vt_ran,
        "score_caption": ("risk from built-in checks only — antivirus "
                          "check not run") if not vt_ran else "",
        "clean_label": "NO KNOWN-BAD FOUND" if score <= 10 else "",
        "findings": findings,
        "facts": facts,
        "facts_display": display,
        "show_safety_guide": score > 10,
    }


# ---------------------------------------------------------------------------
# OmniCheck modes: file, email, text
# ---------------------------------------------------------------------------

def _finish_generic(label, mode, noun, findings, facts, display, started,
                    vt_ran=False):
    """Score findings for file/email/text modes; same report shape as links."""
    score = sum(f.get("points", 0) for f in findings)
    score = max(0, min(100, score))
    if score <= 10:
        verdict = "Safe to open"
        verdict_key = "safe"
        verdict_sub = "Yes — this %s looks safe to open." % noun
    elif score <= 49:
        verdict = "Open with caution"
        verdict_key = "caution"
        verdict_sub = ("Careful — this %s has warning signs. Read the "
                       "findings below before you open it." % noun)
    else:
        verdict = "Do NOT open"
        verdict_key = "dangerous"
        verdict_sub = ("No — do not open this %s. It shows strong signs "
                       "of danger." % noun)
    facts["duration_seconds"] = round(time.time() - started, 1)
    return {
        "url": label,
        "label": label,
        "mode": mode,
        "final_url": label,
        "domain": facts.get("domain"),
        "score": score,
        "verdict": verdict,
        "verdict_key": verdict_key,
        "verdict_sub": verdict_sub,
        "vt_ran": bool(vt_ran),
        "score_caption": ("risk from built-in checks only — antivirus "
                          "check not run") if not vt_ran else "",
        "clean_label": "NO KNOWN-BAD FOUND" if score <= 10 else "",
        "findings": findings,
        "facts": facts,
        "facts_display": display,
        "show_safety_guide": score > 10,
    }


_URL_RE = re.compile(r"https?://[^\s<>'\"()\[\]{}]+", re.IGNORECASE)
_BARE_URL_RE = re.compile(
    r"(?<![\w@/-])(?:www\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?:/[^\s<>'\"()\[\]{}]*)?",
    re.IGNORECASE)


def _extract_urls(text):
    """All http(s) links (plus www. links) found in a piece of text."""
    found = []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?")
        if u not in found:
            found.append(u)
    for m in _BARE_URL_RE.finditer(text or ""):
        u = "https://" + m.group(0).rstrip(".,;:!?")
        if u not in found:
            found.append(u)
    return found


def _quick_url_flags(url):
    """Cheap structural flags for a URL found inside a file/email/message.

    Returns a list of (points, title, detail). No network is used here.
    """
    flags = []
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return flags
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return flags
    if host.startswith("xn--") or any(ord(c) > 127 for c in host):
        flags.append((25, "Look-alike / foreign letters in the link",
                      "The link's address uses punycode or non-Latin "
                      "letters, a classic trick to fake a real website."))
    try:
        ipaddress.ip_address(host)
        flags.append((20, "Link points straight to an IP address",
                      "Real websites use a domain name. Links that point "
                      "directly to an IP address are often used to hide "
                      "where they really go."))
    except ValueError:
        pass
    reg = _registered_domain(host)
    if reg in SHORTENERS:
        flags.append((15, "Link shortener hides the real destination",
                      "The link is shortened, so you cannot see where it "
                      "really goes before clicking it."))
    if reg in TRACKERS:
        flags.append((30, "IP-grabber / tracking link",
                      "This link is made by a service that logs the IP "
                      "address (and more) of anyone who clicks it."))
    tld = reg.rsplit(".", 1)[-1] if "." in reg else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append((10, "Suspicious ending on the link address",
                      "The link ends in .%s, a domain ending often used "
                      "by scam sites." % tld))
    if "@" in (parsed.netloc or ""):
        flags.append((30, "@ trick in the link",
                      "Everything before the @ in a link is ignored — the "
                      "real website is the part after it."))
    deconfused = _deconfuse(host)
    for brand, official in BRANDS.items():
        if brand in deconfused and reg != official \
                and reg not in LEGIT_BRAND_DOMAINS \
                and not reg.endswith("." + official):
            flags.append((30, "Link pretends to be %s" % brand.title(),
                          "The link mentions %s but goes to %s, not the "
                          "real %s site." % (brand, reg, official)))
            break
    return flags


def _check_extracted_links(urls, findings, facts, full_check=2):
    """Link-check URLs found inside a file, email or message.

    Cheap structural flags for every URL; a full live check (same as the
    Link tab) for the first `full_check` URLs. Returns True if any URL
    scored dangerous.
    """
    worst = False
    checked = 0
    for url in urls[:5]:
        done_full = False
        if checked < full_check:
            # Full live check (same as the Link tab) — it already covers
            # the structural tricks, so quick flags are not added as well.
            checked += 1
            try:
                rep = analyze_url(url)
            except Exception:
                rep = {"error": "check failed"}
            if isinstance(rep, dict) and "error" not in rep:
                done_full = True
                if rep["score"] > 10:
                    worst = rep["score"] >= 50
                    _finding(findings,
                             "danger" if rep["score"] >= 50 else "warning",
                             min(rep["score"], 50),
                             "Link inside scores %d — %s" % (
                                 rep["score"], rep["verdict"]),
                             "The link %s was fully checked: %s"
                             % (url[:80], rep["verdict_sub"]))
                else:
                    _finding(findings, "pass", 0,
                             "Link inside is clean: %s" % url[:80],
                             "The link was fully checked and looks safe.")
        if not done_full:
            sub = _quick_url_flags(url)
            if sub:
                pts = min(sum(p for p, _, _ in sub), 40)
                _finding(findings, "warning" if pts < 40 else "danger", pts,
                         "Suspicious link inside: %s" % url[:80],
                         " ".join(d for _, _, d in sub))
    if urls:
        facts["links_found"] = len(urls)
    return worst


def _detect_file_type(data):
    """Real file type from magic bytes; returns (label, usual extensions)."""
    for magic, label, exts in FILE_MAGIC:
        if data.startswith(magic):
            if magic == b"RIFF" and len(data) >= 12:
                kind = data[8:12]
                if kind == b"WEBP":
                    return "WebP image", {".webp"}
                if kind == b"WAVE":
                    return "WAV audio", {".wav"}
                return label, exts
            return label, exts
    try:
        data.decode("utf-8")
        return "Plain text", {".txt", ".log", ".md", ".csv", ".json"}
    except UnicodeDecodeError:
        return "Unknown binary file", set()


def _strings(data, min_len=4):
    """Printable ASCII runs inside raw bytes (like the `strings` tool)."""
    out = []
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def _check_pdf(data, findings):
    """Look for dangerous parts inside a PDF (never executed)."""
    text = data.decode("latin-1", "replace")
    low = text.lower()
    if re.search(r"/(?:javascript|js)(?:\s|/|>>|$)", low):
        _finding(findings, "danger", 30, "JavaScript inside the PDF",
                 "This PDF contains JavaScript. A PDF should only show "
                 "pages — scripts inside a PDF are a known way to attack "
                 "the program that opens it.")
    if "/launch" in low:
        _finding(findings, "danger", 40, "PDF can launch other programs",
                 "This PDF has a /Launch action — opening it can start "
                 "another program on your device. Real documents do not "
                 "need this.")
    if "/embeddedfiles" in low:
        _finding(findings, "warning", 25, "PDF hides other files inside it",
                 "This PDF contains embedded files. They could be "
                 "anything — check them separately before opening.")
    if "/openaction" in low:
        _finding(findings, "warning", 20,
                 "PDF runs something as soon as it opens",
                 "This PDF has an /OpenAction — something happens the "
                 "moment you open it, before you even read it.")
    if "/submitform" in low:
        _finding(findings, "warning", 20, "PDF sends data somewhere",
                 "This PDF has a /SubmitForm action — it can send "
                 "information to a website when you open or fill it.")
    return _extract_urls(text)


def _check_zip(data, filename, findings, display):
    """Inspect a zip (or Office doc) without extracting anything."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        _finding(findings, "warning", 10, "File claims to be a zip but is not",
                 "The file starts like a zip/Office document but its "
                 "contents are broken or fake.")
        return
    names = zf.namelist()
    display.append(["Contents (%d files)" % len(names),
                    ", ".join(names[:12])
                    + (" …" if len(names) > 12 else "")])
    low_names = [n.lower() for n in names]
    if any("vbaproject.bin" in n for n in low_names):
        _finding(findings, "danger", 40, "Macros found in the document",
                 "This document contains macros (VBA code). Macros can "
                 "run programs when the document opens — a classic way "
                 "malware spreads through Word and Excel files.")
    if any(n.endswith(".rels") for n in low_names):
        try:
            for n in names:
                if n.endswith(".rels"):
                    rels = zf.read(n).decode("utf-8", "replace")
                    if 'TargetMode="External"' in rels:
                        _finding(findings, "warning", 10,
                                 "Document links to outside files",
                                 "The document links to files or websites "
                                 "outside itself. Check where they point.")
                        break
        except Exception:
            pass
    if any("/embeddings/" in n for n in low_names):
        _finding(findings, "warning", 15,
                 "Document hides embedded objects",
                 "The document contains embedded objects — they could be "
                 "other files hiding inside it.")
    bad = [n for n in names
           if os.path.splitext(n)[1].lower() in DANGEROUS_EXTS]
    if bad:
        _finding(findings, "danger", 50,
                 "Executable files hidden inside the archive",
                 "This archive contains programs: %s. Opening one can "
                 "run it on your device." % ", ".join(bad[:5]))
    nested = [n for n in names
              if n.lower().endswith((".zip", ".rar", ".7z", ".tar", ".gz"))]
    if nested:
        _finding(findings, "warning", 10, "Nested archives inside",
                 "This archive contains other archives: %s. Each one "
                 "should be checked separately." % ", ".join(nested[:3]))
    if not bad and not nested and not any("vbaproject.bin" in n
                                          for n in low_names):
        _finding(findings, "pass", 0, "Archive contents look normal",
                 "Checked the %d files inside — no programs, macros or "
                 "nested archives." % len(names))


def _check_image(data, findings):
    """Metadata and hidden text inside a picture (never executed)."""
    if b"Exif\x00\x00" in data[:65536]:
        _finding(findings, "info", 0, "Photo metadata (EXIF) found",
                 "This picture has hidden metadata — it can include the "
                 "camera, the date, and sometimes the location where it "
                 "was taken. Sharing it shares that data too.")
    texts = []
    if data.startswith(b"\x89PNG"):
        off = 8
        while off + 8 <= len(data):
            try:
                length = struct.unpack(">I", data[off:off + 4])[0]
            except struct.error:
                break
            ctype = data[off + 4:off + 8]
            chunk = data[off + 8:off + 8 + length]
            if ctype in (b"tEXt", b"iTXt", b"zTXt"):
                texts.append(chunk.decode("utf-8", "replace")[:200])
            off += 12 + length
            if length < 0 or off > len(data):
                break
    if texts:
        _finding(findings, "info", 0, "Text stored inside the picture",
                 "The picture carries hidden text: %s"
                 % "; ".join(texts[:3])[:200])
    return _extract_urls(" ".join(texts))


def analyze_file(data, filename):
    """Analyse one uploaded file (static analysis only — never executed)."""
    started = time.time()
    findings = []
    facts = {"checked_at": datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds") + "Z"}
    name = (filename or "uploaded file").strip() or "uploaded file"
    if not data:
        return {"error": "That file is empty."}
    if len(data) > MAX_FILE_BYTES:
        return {"error": "That file is over 32 MB — too big to check."}
    sha = hashlib.sha256(data).hexdigest()
    facts["sha256"] = sha
    facts["size_bytes"] = len(data)
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    label, exts = _detect_file_type(data)
    facts["detected_type"] = label
    facts["filename"] = name
    display = [["File", name],
               ["Size", "%d bytes (%.1f KB)" % (len(data), len(data) / 1024.0)],
               ["SHA-256", sha],
               ["Real type", label]]
    if exts and ext and ext not in exts:
        _finding(findings, "danger", 35, "File is lying about what it is",
                 "This file is called %s but it is really a %s. Renaming "
                 "a dangerous file to look like a picture or document is "
                 "a classic trick." % (name, label))
    elif ext and ext not in exts and exts:
        _finding(findings, "info", 0, "Unusual extension for this type",
                 "The file says %s but its real type is %s. It is not "
                 "necessarily dangerous, but it is odd." % (ext, label))

    # --- VirusTotal hash lookup (key-gated) ------------------------------
    vt = virustotal_hash_check(sha)
    vt_ran = vt["status"] == "done"
    if vt["status"] == "not_set_up":
        _finding(findings, "info", 0, "VirusTotal: not set up",
                 "Add a free API key (environment variable "
                 "VIRUSTOTAL_API_KEY) to check this file against 70+ "
                 "antivirus engines.")
    elif vt["status"] == "unknown":
        _finding(findings, "info", 0, "VirusTotal: never seen this file",
                 "VirusTotal has never seen this file before — no verdict "
                 "from its engines yet.")
    elif vt["status"] == "error":
        _finding(findings, "info", 0, "VirusTotal: check failed",
                 vt.get("detail", "error") + " — skipped, not a pass.")
    else:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        total = vt.get("total", 0) or 0
        if mal >= 3:
            _finding(findings, "danger", 90,
                     "VirusTotal: %d engines call it malicious" % mal,
                     "%d security engines flag this file as malicious "
                     "and %d as suspicious." % (mal, sus))
        elif mal >= 1:
            _finding(findings, "danger", 50,
                     "VirusTotal: %d engine(s) call it malicious" % mal,
                     "At least one security engine flags this file.")
        elif sus > 0:
            _finding(findings, "warning", 25,
                     "VirusTotal: %d engine(s) call it suspicious" % sus,
                     "No engine calls it malicious, but some find it "
                     "suspicious.")
        else:
            _finding(findings, "pass", 0,
                     "VirusTotal: clean (0 of %d engines)" % total,
                     "No VirusTotal engine flags this file.")

    # --- Type-specific checks ---------------------------------------------
    low_label = label.lower()
    inner_urls = []
    if "pdf" in low_label:
        inner_urls = _check_pdf(data, findings)
    if low_label.startswith("zip") or ext in (".docx", ".xlsx", ".pptx",
                                              ".zip", ".jar", ".apk"):
        _check_zip(data, name, findings, display)
    if "image" in low_label:
        inner_urls = _check_image(data, findings) + inner_urls

    # --- URLs and commands hidden in the file's text ----------------------
    joined = "\n".join(_strings(data))
    low_joined = joined.lower()
    for cmd in ("powershell", "cmd.exe", "rundll32", "mshta.exe",
                "wscript", "cscript"):
        if cmd in low_joined:
            _finding(findings, "warning", 20,
                     "File mentions Windows commands",
                     "The file's text mentions %s — a command attackers "
                     "use to run hidden programs." % cmd)
            break
    file_urls = _extract_urls(joined)
    for u in file_urls:
        if u not in inner_urls:
            inner_urls.append(u)
    if inner_urls:
        _check_extracted_links(inner_urls, findings, facts, full_check=2)
    else:
        _finding(findings, "pass", 0, "No links hidden inside the file",
                 "No website links were found inside the file's text.")

    if not findings:
        _finding(findings, "pass", 0, "Nothing suspicious found",
                 "The built-in checks found nothing wrong with this file.")
    return _finish_generic(name, "file", "file", findings, facts, display,
                           started, vt_ran=vt_ran)


def _scam_word_hits(text):
    """Scam/pressure phrases found in a message (lower-cased)."""
    low = (text or "").lower()
    hits = []
    for phrase in SCAM_PHRASES + URGENCY_WORDS:
        if phrase in low and phrase not in hits:
            hits.append(phrase)
    return hits


def analyze_email(raw):
    """Analyse a pasted email (headers + body)."""
    started = time.time()
    findings = []
    facts = {"checked_at": datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds") + "Z"}
    text = (raw or "").strip()
    if not text:
        return {"error": "Please paste the email first."}
    if len(text) > 200000:
        return {"error": "That email is too long to check."}
    msg = None
    try:
        msg = email.message_from_string(text, policy=email.policy.default)
    except Exception:
        msg = None
    from_hdr = ""
    subject = ""
    received = []
    auth = ""
    body = ""
    if msg is not None:
        from_hdr = str(msg.get("From") or "")
        subject = str(msg.get("Subject") or "")
        received = msg.get_all("Received", []) or []
        auth = str(msg.get("Authentication-Results") or "")
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body += part.get_content() or ""
                        except Exception:
                            pass
            else:
                try:
                    body = msg.get_content() or ""
                except Exception:
                    body = ""
        except Exception:
            body = ""
    if not body:
        body = text
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    from_m = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", from_hdr or "")
    from_addr = from_m.group(0).lower() if from_m else ""
    from_domain = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
    facts["from"] = from_addr or from_hdr or "unknown"
    facts["subject"] = subject or "—"
    facts["received_count"] = len(received)
    display = [["From", facts["from"]],
               ["Subject", facts["subject"]],
               ["Received hops", str(len(received))]]

    # --- Sender vs where it really came from ------------------------------
    if received:
        last = received[-1]
        hop_m = re.search(r"from\s+([A-Za-z0-9.\-]+)", last, re.IGNORECASE)
        hop_host = hop_m.group(1).lower() if hop_m else ""
        hop_domain = _registered_domain(hop_host) if hop_host else ""
        if from_domain and hop_domain and hop_domain != from_domain \
                and hop_domain not in LEGIT_BRAND_DOMAINS:
            _finding(findings, "warning", 25,
                     "Sender address does not match where it came from",
                     "The email says it is from %s, but the last server "
                     "that handled it was %s. Real company mail comes "
                     "from its own servers." % (from_domain, hop_domain))

    # --- SPF / DKIM / DMARC ------------------------------------------------
    if auth:
        low_auth = auth.lower()
        summary = []
        for kind in ("spf", "dkim", "dmarc"):
            m = re.search(kind + r"=(\w+)", low_auth)
            res = m.group(1) if m else "unknown"
            summary.append("%s: %s" % (kind.upper(), res))
            if res == "fail":
                _finding(findings, "warning", 20,
                         "%s check failed" % kind.upper(),
                         "The email failed its %s check — the sender "
                         "could not prove it is really %s."
                         % (kind.upper(), from_domain or "who it claims"))
            elif res == "pass":
                _finding(findings, "pass", 0, "%s check passed"
                         % kind.upper(),
                         "The email passed its %s check."
                         % kind.upper())
        facts["auth"] = "; ".join(summary)
        display.append(["Authentication", facts["auth"]])
    else:
        _finding(findings, "info", 0,
                 "Email authentication could not be checked",
                 "The pasted email has no Authentication-Results header, "
                 "so SPF / DKIM / DMARC could not be verified. Ask your "
                 "mail app to show the full headers, or check the links "
                 "below instead.")

    # --- Brand impersonation -------------------------------------------------
    check_text = ((subject or "") + " " + (from_hdr or "") + " " + body)
    low_check = check_text.lower()
    for brand, official in BRANDS.items():
        if brand in low_check and from_domain \
                and from_domain != official \
                and from_domain not in LEGIT_BRAND_DOMAINS \
                and not from_domain.endswith("." + official):
            _finding(findings, "danger", 35,
                     "Email pretends to be from %s" % brand.title(),
                     "The email talks about %s but it was sent from %s, "
                     "not the real %s. This is how fake bank and service "
                     "emails look." % (brand, from_domain, official))
            break

    # --- Scam / pressure wording --------------------------------------------
    hits = _scam_word_hits(check_text)
    if hits:
        _finding(findings, "warning", min(8 * len(hits), 20),
                 "Scam / pressure wording",
                 "The email uses phrases scammers use: %s."
                 % ", ".join(hits[:4]))

    # --- Risky attachments ---------------------------------------------------
    att_m = re.findall(r"[\w\-. ]+\.(exe|scr|bat|zip|docm|xlsm|pptm|js|apk"
                       r"|jar|msi)\b", body, re.IGNORECASE)
    att = sorted({a.lower() for a in att_m})
    if att:
        danger_exts = {"exe", "scr", "bat", "js", "apk", "jar", "msi"}
        pts = 30 if danger_exts & set(att) else 15
        _finding(findings, "danger" if pts >= 30 else "warning", pts,
                 "Risky attachment mentioned: %s" % ", ".join(att),
                 "The email mentions an attachment ending in .%s. Files "
                 "like that can run code when opened — do not open them "
                 "from an email you did not expect."
                 % ", ".join(att))

    # --- Links inside the email ----------------------------------------------
    urls = _extract_urls(body)
    if urls:
        _check_extracted_links(urls, findings, facts, full_check=2)
        display.append(["Links found", str(len(urls))])
    else:
        _finding(findings, "info", 0, "No links in the email",
                 "The email body contains no website links.")

    label = "Email from %s" % (from_addr or "unknown sender")
    return _finish_generic(label, "email", "email", findings, facts,
                           display, started)


_EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F\u200D]")
_COMMON_WORDS = {"login", "verify", "account", "bank", "secure", "update",
                 "support", "service", "payment", "password", "wallet",
                 "confirm", "security", "official", "helpdesk"}


def analyze_text(raw):
    """Analyse pasted text, emoji and stickers."""
    started = time.time()
    findings = []
    facts = {"checked_at": datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds") + "Z"}
    text = (raw or "").strip()
    if not text:
        return {"error": "Please paste the message first."}
    if len(text) > 100000:
        return {"error": "That message is too long to check."}

    # --- Hidden Unicode tricks ------------------------------------------------
    zw = sum(text.count(c) for c in ZERO_WIDTH)
    bidi = sum(text.count(c) for c in BIDI_CHARS)
    if zw:
        _finding(findings, "warning", 25,
                 "Hidden invisible characters (%d found)" % zw,
                 "The message contains %d invisible characters. They are "
                 "used to hide links or words from spam filters and from "
                 "your eyes." % zw)
    if bidi:
        _finding(findings, "danger", 30,
                 "Right-to-left override trick (%d found)" % bidi,
                 "The message contains characters that flip text "
                 "direction. Scammers use them to make a fake filename "
                 "or link look like something else (for example, a .exe "
                 "file that looks like a .jpg).")
    facts["hidden_chars"] = zw + bidi

    # --- Look-alike (homoglyph) letters ---------------------------------------
    for word in re.split(r"\s+", text):
        if any(c in CONFUSABLES for c in word):
            plain = "".join(CONFUSABLES.get(c, c) for c in word)
            if plain.lower() != word.lower() and (
                    plain.lower() in BRANDS or plain.lower() in _COMMON_WORDS
                    or plain.lower().rstrip(".,;:!?") in BRANDS):
                _finding(findings, "danger", 30,
                         "Look-alike letters: '%s'" % word[:40],
                         "This word uses foreign letters that look like "
                         "Latin ones — it really says '%s'. This is how "
                         "fake brand names are written." % plain[:40])
                break

    # --- Emoji ------------------------------------------------------------------
    emoji_count = len(_EMOJI_RE.findall(text))
    trust_hits = [e for e in TRUST_EMOJI if e in text]
    scam_hits = _scam_word_hits(text)
    low_text = text.lower()
    if trust_hits and (scam_hits or any(b in low_text for b in BRANDS)):
        _finding(findings, "warning", 10,
                 "Fake trust symbols in the message",
                 "The message uses tick/shield/lock emoji to look "
                 "official. Emoji prove nothing — anyone can paste them, "
                 "including scammers.")
    _finding(findings, "info", 0, "About emoji",
             "Emojis are plain Unicode characters — they cannot run code "
             "or harm your device by themselves. Only the tricks around "
             "them (hidden characters, fake links, fake trust symbols) "
             "are dangerous.")
    facts["emoji_count"] = emoji_count

    # --- Scam / pressure wording ----------------------------------------------
    if scam_hits:
        _finding(findings, "warning", min(8 * len(scam_hits), 20),
                 "Scam / pressure wording",
                 "The message uses phrases scammers use: %s."
                 % ", ".join(scam_hits[:4]))

    # --- Links inside the message ----------------------------------------------
    urls = _extract_urls(text)
    if urls:
        _check_extracted_links(urls, findings, facts, full_check=2)
    if any("sticker" in u.lower() for u in urls):
        _finding(findings, "info", 0, "Sticker link found",
                 "A sticker is a picture file. To check the sticker "
                 "itself, save it and check it in the File tab — "
                 "stickers are checked like pictures.")

    display = [["Characters", str(len(text))],
               ["Emoji", str(emoji_count)],
               ["Hidden characters", str(zw + bidi)],
               ["Links found", str(len(urls))]]
    label = "Message: %s" % (text[:80] + ("…" if len(text) > 80 else ""))
    return _finish_generic(label, "text", "message", findings, facts,
                           display, started)


# ---------------------------------------------------------------------------
# Web GUI (dark, professional — one box, one button, one report card)
# ---------------------------------------------------------------------------

PAGE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OmniCheck — Universal Safety Checker</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #0b1220; color: #e2e8f0; min-height: 100vh; }
  .wrap { max-width: 860px; margin: 0 auto; padding: 28px 18px 60px; }
  header { text-align: center; margin-bottom: 22px; }
  header .shield { font-size: 44px; }
  h1 { margin: 6px 0 4px; font-size: 30px; letter-spacing: .3px; }
  .sub { color: #94a3b8; font-size: 15px; }
  .card { background: #111c33; border: 1px solid #1e293b; border-radius: 14px;
          padding: 20px; margin-top: 16px; box-shadow: 0 8px 30px rgba(0,0,0,.35); }
  .row { display: flex; gap: 10px; }
  input[type=url], input[type=text] { flex: 1; padding: 13px 14px; font-size: 16px;
    border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: #f1f5f9;
    outline: none; min-width: 0; }
  input:focus { border-color: #22d3ee; }
  button { padding: 13px 22px; font-size: 16px; font-weight: 700; border: none;
    border-radius: 10px; cursor: pointer; background: #06b6d4; color: #04202b; }
  button:hover { background: #22d3ee; }
  button:disabled { opacity: .55; cursor: wait; }
  .demo { margin-top: 12px; font-size: 13px; color: #94a3b8; }
  .demo a { color: #22d3ee; cursor: pointer; text-decoration: underline; margin-right: 14px; }
  .status { text-align: center; color: #94a3b8; padding: 18px 0 4px; }
  .gauge-wrap { display: flex; gap: 22px; align-items: center; flex-wrap: wrap; }
  .gauge { position: relative; width: 150px; height: 150px; flex: none; }
  .gauge svg { transform: rotate(-90deg); }
  .gauge .num { position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center; }
  .gauge .num b { font-size: 38px; }
  .gauge .num span { font-size: 12px; color: #94a3b8; }
  .verdict { font-size: 26px; font-weight: 800; }
  .verdict.safe { color: #4ade80; } .verdict.caution { color: #fbbf24; }
  .verdict.dangerous { color: #f87171; }
  .verdict-sub { color: #cbd5e1; margin-top: 6px; line-height: 1.5; }
  .find { border-left: 4px solid #475569; background: #0f172a; border-radius: 8px;
    padding: 12px 14px; margin-top: 10px; }
  .find.danger { border-color: #ef4444; } .find.warning { border-color: #f59e0b; }
  .find.pass { border-color: #22c55e; } .find.info { border-color: #64748b; }
  .find b { font-size: 15px; }
  .find .pts { float: right; font-size: 12px; color: #94a3b8; }
  .find p { margin: 5px 0 0; color: #cbd5e1; font-size: 14px; line-height: 1.5; }
  .facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px; margin-top: 6px; }
  .fact { background: #0f172a; border-radius: 8px; padding: 10px 12px; font-size: 13px; }
  .fact b { color: #94a3b8; display: block; font-size: 11px; text-transform: uppercase;
    letter-spacing: .5px; margin-bottom: 3px; }
  .fact span { word-break: break-word; }
  h2 { font-size: 18px; margin: 4px 0 10px; }
  .guide { background: #1c1917; border: 1px solid #78350f; }
  .guide li { margin: 6px 0; line-height: 1.5; color: #fde68a; }
  .actions { display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }
  .actions button { background: #1e293b; color: #e2e8f0; font-weight: 600; padding: 10px 16px; }
  .actions button:hover { background: #334155; }
  .history { font-size: 13px; }
  .history div { padding: 7px 4px; border-bottom: 1px solid #1e293b; cursor: pointer; }
  .history div:hover { background: #0f172a; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 20px; font-size: 12px;
    font-weight: 700; margin-left: 6px; }
  .badge.safe { background: #14532d; color: #4ade80; }
  .badge.caution { background: #451a03; color: #fbbf24; }
  .badge.dangerous { background: #450a0a; color: #f87171; }
  .muted { color: #94a3b8; font-size: 13px; }
  .chain { font-size: 13px; word-break: break-all; line-height: 1.7; }
  .chain .hop { color: #22d3ee; }
  .tabs { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
  .tabs button { background: #0f172a; color: #94a3b8; font-weight: 600; padding: 10px 18px; }
  .tabs button.active { background: #06b6d4; color: #04202b; }
  .tabs button:hover { background: #164e63; color: #e2e8f0; }
  .tabs button.active:hover { background: #22d3ee; color: #04202b; }
  textarea { width: 100%; min-height: 150px; padding: 13px 14px; font-size: 15px;
    border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: #f1f5f9;
    outline: none; resize: vertical; font-family: inherit; }
  textarea:focus { border-color: #22d3ee; }
  .filebox { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .filebox input[type=file] { color: #cbd5e1; font-size: 14px; }
  .cleanbadge { display: inline-block; margin-top: 10px; padding: 4px 12px; border-radius: 20px;
    background: #14532d; color: #4ade80; font-weight: 700; font-size: 13px; }
  .scorecap { color: #94a3b8; font-size: 13px; margin-top: 6px; }
  footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 26px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="shield">&#128737;&#65039;</div>
    <h1>OmniCheck</h1>
    <div class="sub">Link, email, file or message — find out if it is safe to open, and why.</div>
  </header>

  <div class="card">
    <div class="tabs">
      <button id="tab-link" class="active" onclick="showTab('link')">Link</button>
      <button id="tab-email" onclick="showTab('email')">Email</button>
      <button id="tab-file" onclick="showTab('file')">File</button>
      <button id="tab-text" onclick="showTab('text')">Text</button>
    </div>

    <div id="panel-link">
      <div class="row">
        <input id="url" type="text" placeholder="Paste a link here, e.g. https://example.com/login" autocomplete="off" spellcheck="false">
        <button id="checkBtn" onclick="checkInput()">Check</button>
      </div>
      <div class="demo">Try it:
        <a onclick="demo('https://www.paypal.com/signin')">Safe example — PayPal sign-in</a>
        <a onclick="demo('https://secure-paypal-verify.top/signin')">Fake look-alike</a>
        <a onclick="demo('https://grabify.link/ABC123')">Grabify tracking link</a>
      </div>
    </div>

    <div id="panel-email" style="display:none">
      <textarea id="emailText" placeholder="Paste the full email here — headers and body (From, Subject, links, everything)." spellcheck="false"></textarea>
      <div class="row" style="margin-top:10px">
        <button id="checkBtnEmail" onclick="checkInput()">Check email</button>
        <button onclick="demoEmail()" style="background:#1e293b;color:#e2e8f0;font-weight:600">Try a fake PayPal email</button>
      </div>
      <div class="demo">Tip: in your mail app use “Show original” / “View headers” and copy everything.</div>
    </div>

    <div id="panel-file" style="display:none">
      <div class="filebox">
        <input id="fileInput" type="file">
        <button id="checkBtnFile" onclick="checkInput()">Check file</button>
      </div>
      <div class="demo">Picture, PDF, Word/Excel/PowerPoint, zip, or any file — max 32 MB. The file is never run, only read.</div>
      <div class="demo" id="fileName"></div>
    </div>

    <div id="panel-text" style="display:none">
      <textarea id="msgText" placeholder="Paste a message, text or emoji here — a prize message, a bank warning, anything suspicious." spellcheck="false"></textarea>
      <div class="row" style="margin-top:10px">
        <button id="checkBtnText" onclick="checkInput()">Check message</button>
        <button onclick="demoText()" style="background:#1e293b;color:#e2e8f0;font-weight:600">Try a prize scam message</button>
      </div>
      <div class="demo">For a sticker file, use the File tab — stickers are checked like pictures.</div>
    </div>
  </div>

  <div id="status" class="status"></div>
  <div id="result"></div>
  <div id="historyCard" class="card history" style="display:none">
    <h2>Checked this session</h2>
    <div id="history"></div>
  </div>

  <footer>Defensive tool only — it reads links, emails, files and messages and warns you. It never creates
  phishing pages, never captures passwords, never runs uploaded files, and stores nothing on the server.</footer>
</div>

<script>
let lastReport = null;

let activeTab = 'link';

function showTab(name) {
  activeTab = name;
  ['link', 'email', 'file', 'text'].forEach(function (t) {
    document.getElementById('tab-' + t).className = (t === name ? 'active' : '');
    document.getElementById('panel-' + t).style.display = (t === name ? '' : 'none');
  });
  document.getElementById('status').textContent = '';
}

function demo(u) { showTab('link'); document.getElementById('url').value = u; checkInput(); }

function demoEmail() {
  showTab('email');
  document.getElementById('emailText').value =
    'From: PayPal Security <security@paypa1-secure.top>\n'
    + 'Subject: Urgent: verify your account now\n'
    + 'Date: Fri, 20 Nov 2026 10:00:00 +0000\n'
    + 'Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\n'
    + 'Received: from mail.paypa1-secure.top (185.220.101.5) by mx.example.com\n\n'
    + 'Dear customer,\n\n'
    + 'We detected unusual activity on your PayPal account. Your account will be closed within 24 hours unless you verify your identity now.\n\n'
    + 'Click here to verify: https://secure-paypal-verify.top/signin\n\n'
    + 'Act now or lose access to your money.\n\nPayPal Security Team';
  checkInput();
}

function demoText() {
  showTab('text');
  document.getElementById('msgText').value =
    '🎉 CONGRATULATIONS! You have won a FREE iPhone 15! ✅✅\n'
    + 'Click here to claim your prize now: https://prize-claim-winner.top/free-iphone\n'
    + 'Hurry — limited time offer! Send your bank details to verify. 🔒';
  checkInput();
}

document.getElementById('url').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') checkInput();
});

document.getElementById('fileInput').addEventListener('change', function () {
  const f = this.files[0];
  document.getElementById('fileName').textContent = f
    ? ('Selected: ' + f.name + ' (' + (f.size / 1024).toFixed(1) + ' KB)')
    : '';
});

function readFileAsBase64(file) {
  return new Promise(function (resolve, reject) {
    const reader = new FileReader();
    reader.onload = function () {
      const res = String(reader.result || '');
      resolve(res.indexOf(',') >= 0 ? res.split(',')[1] : res);
    };
    reader.onerror = function () { reject(new Error('could not read file')); };
    reader.readAsDataURL(file);
  });
}

async function checkInput() {
  const status = document.getElementById('status');
  const result = document.getElementById('result');
  let body = null;
  let busy = 'Checking…';
  if (activeTab === 'link') {
    const url = document.getElementById('url').value.trim();
    if (!url) { status.textContent = 'Please paste a link first.'; return; }
    body = {mode: 'link', url: url};
    busy = 'Checking URL tricks, redirects, domain age, DNS, certificate, page content and live threat databases…';
  } else if (activeTab === 'email') {
    const text = document.getElementById('emailText').value.trim();
    if (!text) { status.textContent = 'Please paste the email first.'; return; }
    body = {mode: 'email', text: text};
    busy = 'Checking sender, authentication, links and wording…';
  } else if (activeTab === 'file') {
    const file = document.getElementById('fileInput').files[0];
    if (!file) { status.textContent = 'Please choose a file first.'; return; }
    if (file.size > 32 * 1024 * 1024) { status.textContent = 'That file is over 32 MB — too big to check.'; return; }
    status.textContent = 'Reading file…';
    let data;
    try { data = await readFileAsBase64(file); }
    catch (e) { status.textContent = 'Could not read that file.'; return; }
    body = {mode: 'file', filename: file.name, data: data};
    busy = 'Checking file type, hash, hidden content and links inside…';
  } else {
    const text = document.getElementById('msgText').value.trim();
    if (!text) { status.textContent = 'Please paste the message first.'; return; }
    body = {mode: 'text', text: text};
    busy = 'Checking wording, hidden characters, emoji tricks and links…';
  }
  const btn = document.querySelector('#panel-' + activeTab + ' button');
  if (btn) { btn.disabled = true; }
  status.textContent = busy;
  result.innerHTML = '';
  try {
    const resp = await fetch('/api/check', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (data.error) { status.textContent = data.error; return; }
    lastReport = data;
    render(data);
    addHistory(data);
    status.textContent = '';
  } catch (e) {
    status.textContent = 'Could not reach OmniCheck: ' + e.message;
  } finally {
    if (btn) { btn.disabled = false; }
  }
}

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function gaugeColor(score) {
  if (score <= 10) return '#22c55e';
  if (score <= 49) return '#f59e0b';
  return '#ef4444';
}

function render(r) {
  const color = gaugeColor(r.score);
  const circ = 2 * Math.PI * 60;
  const off = circ * (1 - r.score / 100);
  const vclass = r.verdict_key;
  const verdictText = r.verdict_sub || '';
  let h = '<div class="card"><div class="gauge-wrap">'
    + '<div class="gauge"><svg width="150" height="150">'
    + '<circle cx="75" cy="75" r="60" fill="none" stroke="#1e293b" stroke-width="12"/>'
    + '<circle cx="75" cy="75" r="60" fill="none" stroke="' + color + '" stroke-width="12"'
    + ' stroke-linecap="round" stroke-dasharray="' + circ.toFixed(1) + '"'
    + ' stroke-dashoffset="' + off.toFixed(1) + '"/></svg>'
    + '<div class="num"><b>' + r.score + '</b><span>risk / 100</span></div></div>'
    + '<div><div class="verdict ' + vclass + '">' + esc(r.verdict) + '</div>'
    + '<div class="verdict-sub">' + verdictText + '</div>'
    + '<div class="muted" style="margin-top:8px">Checked: ' + esc(r.label || r.url)
    + (r.mode === 'link' && r.final_url && r.final_url !== r.url ? '<br>Finally opens: ' + esc(r.final_url) : '')
    + '</div>'
    + (r.clean_label ? '<div><span class="cleanbadge">' + esc(r.clean_label) + '</span></div>' : '')
    + (r.score_caption ? '<div class="scorecap">' + esc(r.score_caption) + '</div>' : '')
    + '</div></div>';

  h += '<h2 style="margin-top:22px">What was found</h2>';
  const order = {danger: 0, warning: 1, info: 2, pass: 3};
  const sorted = r.findings.slice().sort((a, b) => order[a.level] - order[b.level]);
  for (const f of sorted) {
    h += '<div class="find ' + f.level + '"><b>' + esc(f.title) + '</b>'
      + (f.points ? '<span class="pts">+' + f.points + ' risk</span>' : '')
      + '<p>' + esc(f.detail) + '</p></div>';
  }

  const facts = r.facts || {};
  h += '<h2 style="margin-top:22px">Facts</h2><div class="facts">';
  (r.facts_display || []).forEach(function (pair) {
    h += fact(pair[0], pair[1]);
  });
  if (facts.redirects && facts.redirects.length > 1) {
    h += '</div><h2 style="margin-top:16px">Redirect chain</h2><div class="chain">'
      + facts.redirects.map(function (hop, i) {
          return (i + 1) + '. <span class="hop">' + esc(hop.url) + '</span> → ' + hop.status;
        }).join('<br>') + '</div><div class="facts">';
  }
  h += '</div>';

  if (r.show_safety_guide) {
    h += '<div class="card guide"><h2>How to confirm before opening</h2><ul>'
      + '<li>Type the official website address yourself instead of clicking the link.</li>'
      + '<li>Check the sender\u2019s real email address — not just the display name.</li>'
      + '<li>Open the service through its official app or website, not through the link.</li>'
      + '<li>Never enter a password or OTP after clicking a link from an email or message.</li>'
      + '<li>If you are unsure, contact the company through its official website or support channel.</li>'
      + '</ul><h2>If you must open it</h2><ul>'
      + '<li>Use a separate browser profile or incognito window with no saved logins.</li>'
      + '<li>Do not download any files from it.</li>'
      + '<li>Do not enter credentials or payment details.</li>'
      + '</ul></div>';
  }

  h += '<div class="actions"><button onclick="copyReport()">Copy report</button>'
    + '<button onclick="downloadReport()">Download report (.txt)</button></div></div>';
  document.getElementById('result').innerHTML = h;
  window.scrollTo({top: document.getElementById('result').offsetTop - 10, behavior: 'smooth'});
}

function fact(label, value) {
  return '<div class="fact"><b>' + esc(label) + '</b><span>' + esc(value) + '</span></div>';
}

function reportText(r) {
  let t = 'OmniCheck report\\n';
  t += 'Checked: ' + (r.label || r.url) + '\\n';
  if (r.mode === 'link') t += 'Final URL: ' + r.final_url + '\\n';
  t += 'Risk score: ' + r.score + '/100 — ' + r.verdict + '\\n';
  if (r.clean_label) t += r.clean_label + '\\n';
  if (r.score_caption) t += r.score_caption + '\\n';
  t += '\\n';
  for (const f of r.findings) {
    t += '[' + f.level.toUpperCase() + (f.points ? ' +' + f.points : '') + '] '
      + f.title + '\\n  ' + f.detail + '\\n';
  }
  return t;
}

function copyReport() {
  if (!lastReport) return;
  navigator.clipboard.writeText(reportText(lastReport)).then(function () {
    alert('Report copied.');
  });
}

function downloadReport() {
  if (!lastReport) return;
  const blob = new Blob([reportText(lastReport)], {type: 'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'omnicheck-report.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}

function addHistory(r) {
  try {
    let hist = JSON.parse(sessionStorage.getItem('omnicheck-history') || '[]');
    hist.unshift({url: r.label || r.url, mode: r.mode, score: r.score, verdict: r.verdict, key: r.verdict_key});
    hist = hist.slice(0, 10);
    sessionStorage.setItem('omnicheck-history', JSON.stringify(hist));
    const box = document.getElementById('history');
    document.getElementById('historyCard').style.display = '';
    box.innerHTML = hist.map(function (item) {
      return '<div data-url="' + esc(item.url) + '" data-mode="' + esc(item.mode || 'link') + '">'
        + esc(item.url.length > 70 ? item.url.slice(0, 70) + '…' : item.url)
        + '<span class="badge ' + item.key + '">' + item.score + ' · ' + esc(item.verdict) + '</span></div>';
    }).join('');
    box.querySelectorAll('div').forEach(function (el) {
      el.addEventListener('click', function () {
        if (el.getAttribute('data-mode') === 'link') {
          showTab('link');
          document.getElementById('url').value = el.getAttribute('data-url');
          checkInput();
        }
      });
    });
  } catch (e) { /* session storage unavailable — ignore */ }
}
</script>
</body>
</html>
'''


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/health":
            self._send_json({"ok": True, "version": VERSION})
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path != "/api/check":
            self._send_json({"error": "not found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        # File uploads (base64) can be large: 32 MB file = ~43 MB base64.
        if length <= 0 or length > 48 * 1024 * 1024:
            self._send_json({"error": "Bad request."}, status=400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._send_json({"error": "Bad request."}, status=400)
            return
        mode = (payload.get("mode") or "link").strip().lower()
        try:
            if mode == "link":
                url = (payload.get("url") or "").strip()
                if not url:
                    self._send_json(
                        {"error": "Please paste a link first."})
                    return
                report = analyze_url(url)
            elif mode == "email":
                text = payload.get("text") or ""
                if not text.strip():
                    self._send_json(
                        {"error": "Please paste the email first."})
                    return
                report = analyze_email(text)
            elif mode == "text":
                text = payload.get("text") or ""
                if not text.strip():
                    self._send_json(
                        {"error": "Please paste the message first."})
                    return
                report = analyze_text(text)
            elif mode == "file":
                filename = (payload.get("filename") or "uploaded file")
                data_b64 = payload.get("data") or ""
                if "," in data_b64:  # tolerate a data: URL prefix
                    data_b64 = data_b64.split(",", 1)[1]
                if not data_b64:
                    self._send_json(
                        {"error": "Please choose a file first."})
                    return
                try:
                    data = base64.b64decode(data_b64, validate=True)
                except Exception:
                    self._send_json(
                        {"error": "That file could not be read."})
                    return
                report = analyze_file(data, filename)
            else:
                self._send_json({"error": "Unknown check type."})
                return
        except Exception as e:  # never crash the server on a bad input
            report = {"error": "Check failed: %s" % _short_err(e)}
        self._send_json(report)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("OmniCheck v%s" % VERSION)
    print("Open in your browser: http://%s:%d" % (HOST, PORT))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
