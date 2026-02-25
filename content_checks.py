"""
Content Identity Verification
==============================
Detects domains that pass DNS/email infrastructure checks but have
suspicious web content: cloned pages, identity mismatches, domain
broker facades, cross-domain email references.

Plugs into analyzer.py alongside VirusTotal and hacklink checks.
Reuses pre-fetched page content (no duplicate HTTP requests).

VERSION: 1.0 (Feb 2026)
- Title vs body identity mismatch
- Cross-domain email detection (kigs.app showing @topdot.com emails)
- Privacy/freemail/disposable email on business page
- Domain broker / parking / for-sale detection
- Placeholder / template content detection
- Content + structure hashing for cross-domain clone detection
"""

import re
import hashlib
import logging
from typing import Dict, List

log = logging.getLogger("content_checks")


# ─────────────────────────────────────────────
# REFERENCE DATA
# ─────────────────────────────────────────────

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "icloud.com", "zoho.com", "yandex.com", "gmx.com",
    "live.com", "msn.com", "yahoo.co.uk", "googlemail.com",
}

PRIVACY_EMAIL_DOMAINS = {
    "protonmail.com", "proton.me", "pm.me",
    "tutanota.com", "tuta.io", "tutanota.de",
    "hushmail.com", "mailfence.com",
    "disroot.org", "riseup.net", "cock.li", "airmail.cc",
}

DISPOSABLE_EMAIL_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "throwaway.email",
    "mailinator.com", "sharklasers.com", "yopmail.com",
    "trashmail.com", "10minutemail.com", "temp-mail.org",
}

BROKER_PARKING_PHRASES = [
    "domain brokerage", "domain broker", "domain for sale",
    "buy this domain", "purchase this domain", "make an offer",
    "domain acquisition", "premium domain", "domain portfolio",
    "submit inquiry", "domain monetization", "domain search",
    "parked domain", "this domain is for sale", "inquire about",
    "domain transfer", "domain escrow", "domain appraisal",
    "brokerage services", "domain services", "domain marketplace",
    "featured domains", "find your perfect domain",
    "domain provider", "portfolio management",
]

PLACEHOLDER_PHRASES = [
    "lorem ipsum", "coming soon", "under construction",
    "website coming soon", "page under construction",
    "sample page", "hello world", "default page", "test page",
]

IGNORE_EMAIL_DOMAINS = {
    "cloudflare.com", "google.com", "wordpress.com", "gravatar.com",
    "w3.org", "schema.org", "sentry.io", "googleapis.com",
    "gstatic.com", "facebook.com", "twitter.com", "github.com",
}


# ─────────────────────────────────────────────
# EXTRACTION HELPERS
# ─────────────────────────────────────────────

def _extract_emails(html: str) -> List[str]:
    return list(set(re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
    )))

def _extract_phones(text: str) -> List[str]:
    patterns = [
        r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
    ]
    phones = []
    for p in patterns:
        phones.extend(re.findall(p, text))
    return list(set(phones))

def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.DOTALL)
    return match.group(1).strip() if match else ""

def _visible_text(html: str) -> str:
    text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.I)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def _content_hash(text: str) -> str:
    normalized = re.sub(r"\d+", "", text.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()

def _structure_hash(html: str) -> str:
    tags = re.findall(r"<(/?\w+)", html)
    return hashlib.sha256(" ".join(tags[:500]).encode()).hexdigest()


# ─────────────────────────────────────────────
# MAIN CHECK FUNCTION
# ─────────────────────────────────────────────

def check_content_identity(domain: str, content: str = "") -> Dict:
    """
    Run content identity checks on pre-fetched page content.

    Args:
        domain: The domain being checked (e.g., "kigs.app")
        content: Pre-fetched HTML string (from analyzer's existing fetch)

    Returns:
        Dict with all findings — stored on DomainApprovalResult fields
    """
    result = {
        "title_body_mismatch": False,
        "title_body_mismatch_detail": "",
        "cross_domain_emails": [],
        "cross_domain_email_domains": [],
        "page_privacy_emails": [],
        "page_freemail_contacts": [],
        "page_disposable_emails": [],
        "is_broker_page": False,
        "broker_indicators": [],
        "is_placeholder": False,
        "placeholder_phrases": [],
        "page_emails": [],
        "page_phones": [],
        "content_hash": "",
        "structure_hash": "",
        "title": "",
    }

    if not content or len(content) < 50:
        return result

    html = content
    title = _extract_title(html)
    visible = _visible_text(html)
    emails = _extract_emails(html)
    phones = _extract_phones(visible)

    result["title"] = title
    result["page_emails"] = emails
    result["page_phones"] = phones
    result["content_hash"] = _content_hash(visible)
    result["structure_hash"] = _structure_hash(html)

    domain_lower = domain.lower()
    domain_base = domain_lower.split(".")[0]

    # ── CHECK 1: Title vs Body mismatch ──
    if title and len(visible) > 200:
        title_words = set(re.findall(r"\b[a-z]{4,}\b", title.lower()))
        stopwords = {"this", "that", "with", "from", "your", "have", "been",
                     "will", "about", "more", "what", "when", "which", "their",
                     "other", "some", "than", "into", "over", "just", "also",
                     "home", "page", "site", "welcome"}
        title_words -= stopwords

        if title_words:
            matches = sum(1 for w in title_words if w in visible.lower())
            ratio = matches / len(title_words)
            if ratio < 0.25:
                result["title_body_mismatch"] = True
                result["title_body_mismatch_detail"] = (
                    f"Title '{title}' — {matches}/{len(title_words)} "
                    f"keywords found in body ({ratio:.0%} match)"
                )

    # ── CHECK 2: Cross-domain emails ──
    for email in emails:
        if "@" not in email:
            continue
        email_domain = email.split("@")[1].lower()
        if email_domain in IGNORE_EMAIL_DOMAINS:
            continue
        if email_domain == domain_lower:
            continue
        if domain_base in email_domain or email_domain.split(".")[0] in domain_lower:
            continue
        result["cross_domain_emails"].append(email)
        if email_domain not in result["cross_domain_email_domains"]:
            result["cross_domain_email_domains"].append(email_domain)

    # ── CHECK 3: Privacy / freemail / disposable on page ──
    for email in emails:
        if "@" not in email:
            continue
        email_domain = email.split("@")[1].lower()
        if email_domain in PRIVACY_EMAIL_DOMAINS:
            result["page_privacy_emails"].append(email)
        elif email_domain in DISPOSABLE_EMAIL_DOMAINS:
            result["page_disposable_emails"].append(email)
        elif email_domain in FREEMAIL_DOMAINS:
            result["page_freemail_contacts"].append(email)

    # ── CHECK 4: Domain broker / parking / for-sale page ──
    text_lower = visible.lower()
    matched_phrases = [p for p in BROKER_PARKING_PHRASES if p in text_lower]
    result["broker_indicators"] = matched_phrases
    if len(matched_phrases) >= 3:
        result["is_broker_page"] = True

    # ── CHECK 5: Placeholder / template content ──
    matched_placeholders = [p for p in PLACEHOLDER_PHRASES if p in text_lower]
    result["placeholder_phrases"] = matched_placeholders
    if matched_placeholders:
        result["is_placeholder"] = True

    return result
