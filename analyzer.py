from __future__ import annotations
"""
Domain Analysis Engine for Sender Approval
==========================================
Core analysis logic extracted for use in web app.

VERSION: 7.2 (Feb 2026)
- MALICIOUS SCRIPT detection overhaul: replaced broad single-regex SocGholish pattern
  with multi-signal scoring architecture (10 weighted signals, CDN whitelist, Shannon
  entropy path analysis, NDSW/NDSX pattern matching)
- CDN WHITELIST: 50+ known-good script domains excluded from detection to eliminate
  false positives from legitimate React/Angular/Vue SPAs loading jQuery, Analytics, etc.
- CONFIDENCE LEVELS: malicious_script now reports HIGH (5+ signal score, full weight)
  or MEDIUM (3-4 signal score, reduced weight) instead of binary flag
- New config weight: malicious_script_medium (default 25) for MEDIUM-confidence detections
- New result fields: hacklink_malicious_script_confidence, hacklink_malicious_script_signals,
  hacklink_malicious_script_score

VERSION: 7.1 (Feb 2026)
- MALICIOUS SCRIPT detection: SocGholish/FakeUpdates/obfuscated script injection scored as
  standalone high-weight signal (40 pts) — extracted from hacklink scanner's injection_patterns
- HIDDEN INJECTION detection: CSS-cloaked content (display:none, font-size:0px, negative
  text-indent) scored standalone (35 pts) — the #1 indicator of hacklink SEO spam
- cPanel hosting detection: surfaced from hacklink scanner as cpanel_detected signal
- WHOIS enrichment: registrar, statuses, updated date, transfer lock status extracted
  via python-whois for every scanned domain
- TRANSFER LOCK detection: domains missing clientTransferProhibited flagged (12 pts);
  combo with old domain age = domain takeover signal
- WHOIS recently updated: domains with WHOIS changes in last 30 days flagged (8 pts);
  combo with cPanel = compromise indicator
- EMPTY PAGE detection: reachable domains returning <50 bytes flagged (15 pts)
- CERTIFICATE TRANSPARENCY (crt.sh): cert count, issuers, first/last seen, recent
  issuance (7d); zero CT history = never-used domain (12 pts); recent issuance on
  old domain = takeover/reactivation signal
- 10 new combo rules: cpanel+transfer_lock, vt+hacklink_keywords, transfer_lock+old_domain,
  malicious_script combos, hidden_injection combos, empty_page combos

VERSION: 7.0 (Feb 2026)
- Integrated VirusTotal domain reputation check (malicious/suspicious vendor counts,
  threat names, community score, detection rate)
- Integrated hacklink/SEO spam detection (Turkish hacklink keywords, injection patterns,
  WordPress compromise indicators, vulnerable plugin detection, spam link counting)
- Hacklink scanner reuses pre-fetched page content — no duplicate HTTP requests
- New VT scoring signals: vt_malicious_high/medium/low, vt_suspicious, vt_clean (bonus)
- New hacklink scoring signals: hacklink_detected, hacklink_keywords, hacklink_wp_compromised,
  hacklink_vulnerable_plugins, hacklink_spam_links
- 15 new combo rules for VT + hacklink cross-correlation
- VT API key configurable via admin UI, sidebar, or VT_API_KEY env var

VERSION: 6.3 (Feb 2026)
- Added WHOIS fallback when RDAP returns no creation date (python-whois)
- New signal: domain_created_today — fires when domain registered 0-1 days ago
- Heavy base penalty (50) + combo rules for brand impersonation, blacklist, typosquat, TLD spoof
- New fields: whois_created, domain_age_source, domain_created_today
- Summary prominently flags same-day/yesterday registrations

VERSION: 6.2 (Feb 2026)
- Fixed DNSBL rate limit bug: blacklist checks silently returning "clean" on timeout
- check_blacklist() now distinguishes NXDOMAIN (clean) from timeout/error (inconclusive)
- Added retry with backoff for failed DNSBL queries (2 retries, 1.5s delay)
- Added inter-query delay (0.3s) between consecutive DNSBL lookups to avoid bursts
- Added in-memory DNSBL result cache (5min TTL) to prevent redundant queries
- New fields: domain_blacklist_inconclusive, ip_blacklist_inconclusive
- Inconclusive blacklist checks flagged in summary + add configurable score penalty (default 15)

VERSION: 5.2 (Feb 2026)
- Added brand + spoofing keyword detection (easyjetconnect, amazonverify, etc.)
- Expanded IMPERSONATED_BRANDS to include airlines, travel, banks, shipping, telecoms
- New signal: brand_spoofing_keyword — fires when brand name + phishing keyword detected
- Brand+keyword scores on top of domain_brand_impersonation for amplified risk

VERSION: 4.7 (Feb 2026)
- Added TLD variant spoofing detection (gordondown.uk → gordondown.co.uk pattern)
- Generates TLD variants (.uk↔.co.uk, .com, .io↔.com, etc.)
- Compares content volume, email infrastructure, and business identity asymmetry
- Flags when established business exists at variant TLD and signup domain is hollow

VERSION: 4.6 (Feb 2026)
- Added hosting provider detection (NS records, ASN lookup, PTR patterns)
- Configurable scoring tiers: budget shared hosts, free hosting, suspect hosts
- ASN lookup via Team Cymru DNS for reliable network identification

VERSION: 4.5 (Feb 2026)
- Added app store presence detection (iOS AASA, Android Asset Links, page scan, iTunes API)
- App store presence as legitimacy bonus signal (rare for spammers to maintain real apps)
- Confidence-tiered scoring: high/medium/low app presence → scaled bonus

VERSION: 4.4 (Feb 2026)
- Added explicit TLS handshake failure detection (ssl.SSLError catch)
- Added tls_handshake_failed / tls_connection_failed flags + scoring
- Fixed bare except in follow_redirects (typed error capture)
- Added e-commerce/retail scam detection (.shop, .store, .sale TLDs)
- Added cross-domain brand link detection (clone store indicator)
- Added business identity verification for e-commerce sites
- Added non-hyphen prefix detection (app, my, login, etc.)
- Added access restriction detection (401/403)
"""

ANALYZER_VERSION = "7.2"

import re
import json
import os
import socket
import ssl
import hashlib
import difflib
from dataclasses import dataclass, fields, asdict
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Set
from urllib.parse import urlparse, urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from config import DEFAULT_CONFIG, get_weight

try:
    from app_store_detection import check_app_store_presence
    APP_STORE_DETECTION_AVAILABLE = True
except Exception:
    APP_STORE_DETECTION_AVAILABLE = False

try:
    from virustotal_checker import VirusTotalChecker
    VT_CHECKER_AVAILABLE = True
except Exception:
    VT_CHECKER_AVAILABLE = False

try:
    from hacklink_keyword_scanner import HacklinkKeywordScanner
    HACKLINK_SCANNER_AVAILABLE = True
except Exception:
    HACKLINK_SCANNER_AVAILABLE = False


# ============================================================================
# DATA CLASS
# ============================================================================

@dataclass
class DomainApprovalResult:
    # === PRIMARY FIELDS ===
    domain: str = ""
    risk_score: int = 0
    recommendation: str = ""
    summary: str = ""
    
    # === METADATA ===
    scan_timestamp: str = ""
    risk_level: str = ""
    
    # === DNS / NETWORK ===
    resolved: bool = False
    ip_address: str = ""
    
    # === REVERSE DNS (PTR) ===
    ptr_record: str = ""
    ptr_exists: bool = False
    ptr_matches_forward: bool = False
    
    # === EMAIL: SPF ===
    spf_record: str = ""
    spf_exists: bool = False
    spf_mechanism: str = ""
    spf_includes: str = ""
    spf_lookup_count: int = 0
    spf_syntax_valid: bool = True
    spf_too_permissive: bool = False
    
    # === EMAIL: DKIM ===
    dkim_exists: bool = False
    dkim_selectors_found: str = ""
    
    # === EMAIL: DMARC ===
    dmarc_record: str = ""
    dmarc_exists: bool = False
    dmarc_policy: str = ""
    dmarc_pct: int = 100
    dmarc_rua: str = ""
    dmarc_syntax_valid: bool = True
    
    # === EMAIL: MX ===
    mx_exists: bool = False
    mx_records: str = ""
    mx_is_null: bool = False
    mx_uses_free_provider: bool = False
    mx_primary: str = ""
    mx_provider_type: str = ""  # "enterprise", "standard", "disposable", "selfhosted", "unknown"
    mx_is_mail_prefix: bool = False  # MX is exactly mail.{domain} — phishing template fingerprint
    
    # === EMAIL: SPF PROVIDER ANALYSIS ===
    spf_has_external_includes: bool = False  # SPF includes a real email provider (Google, Microsoft, etc.)
    
    # === EMAIL: BIMI ===
    bimi_exists: bool = False
    bimi_record: str = ""
    
    # === EMAIL: MTA-STS ===
    mta_sts_exists: bool = False
    mta_sts_record: str = ""
    
    # === BLACKLISTS ===
    domain_blacklists_hit: str = ""
    domain_blacklist_count: int = 0
    domain_blacklist_inconclusive: int = 0    # v6.2: queries that timed out / errored
    ip_blacklists_hit: str = ""
    ip_blacklist_count: int = 0
    ip_blacklist_inconclusive: int = 0        # v6.2: queries that timed out / errored
    
    # === DOMAIN INFO ===
    rdap_created: str = ""
    whois_created: str = ""
    domain_age_days: int = -1
    domain_age_source: str = ""                  # "rdap" or "whois"
    domain_created_today: bool = False            # True if 0-1 days old
    is_suspicious_tld: bool = False
    is_free_email_domain: bool = False
    is_free_hosting: bool = False
    is_url_shortener: bool = False
    is_disposable_email: bool = False
    typosquat_target: str = ""
    typosquat_similarity: float = 0.0
    
    # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
    has_suspicious_prefix: bool = False
    suspicious_prefix_found: str = ""
    has_suspicious_suffix: bool = False
    suspicious_suffix_found: str = ""
    is_tech_support_tld: bool = False
    domain_impersonates_brand: str = ""  # Brand found in domain name
    domain_pattern_risk: str = ""  # Summary of suspicious patterns
    brand_spoofing_keyword: str = ""     # Spoofing keyword found with brand (e.g., "connect" in easyjetconnect)
    brand_plus_keyword_domain: bool = False  # True when brand + spoofing keyword detected
    
    # === WEB: TLS/CERT ===
    https_valid: bool = False
    tls_error: str = ""
    tls_handshake_failed: bool = False       # v4.4: True when SSL handshake itself fails
    tls_connection_failed: bool = False       # v4.4: True when TCP connect to 443 fails
    cert_self_signed: bool = False
    cert_expired: bool = False
    cert_wrong_host: bool = False
    
    # === WEB: HTTP ===
    http_reachable: bool = False
    http_status: int = 0
    https_reachable: bool = False
    https_status: int = 0
    
    # === WEB: REDIRECTS ===
    redirect_count: int = 0
    redirect_chain: str = ""
    redirect_domains: str = ""
    redirect_cross_domain: bool = False
    redirect_uses_temp: bool = False
    final_url: str = ""
    
    # === WEB: STATUS CODES ===
    status_codes_seen: str = ""
    has_403: bool = False
    has_429: bool = False
    has_503: bool = False
    has_5xx: bool = False
    
    # === WEB: CONTENT ===
    content_length: int = -1
    content_hash: str = ""
    is_minimal_shell: bool = False
    has_js_redirect: bool = False
    has_meta_refresh: bool = False
    has_external_js: bool = False
    has_obfuscation: bool = False
    
    # === PHISHING/MALWARE ===
    phishing_paths_found: str = ""
    has_credential_form: bool = False
    has_sensitive_fields: bool = False
    brands_detected: str = ""
    form_posts_external: bool = False
    malware_links_found: str = ""
    has_suspicious_iframe: bool = False
    is_parking_page: bool = False
    
    # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
    has_hijack_path_pattern: bool = False
    hijack_path_found: str = ""
    has_doc_sharing_lure: bool = False
    doc_lure_found: str = ""
    has_phishing_js_behavior: bool = False
    phishing_js_patterns: str = ""
    redirects_to_phishing_infra: bool = False
    phishing_infra_domain: str = ""
    has_email_in_url: bool = False
    url_email_tracking: str = ""
    
    # === ACCESS ANOMALY DETECTION ===
    has_401: bool = False                    # 401 Unauthorized seen
    is_access_restricted: bool = False       # 401/403 on public-facing domain
    access_restriction_note: str = ""        # Details about access restriction
    
    # === CORPORATE TRUST SIGNALS ===
    missing_trust_signals: bool = False      # No about/contact/privacy pages
    trust_pages_checked: str = ""            # Which pages were checked
    trust_pages_found: str = ""              # Which trust pages exist
    is_opaque_entity: bool = False           # Access restricted + no trust signals
    
    # === E-COMMERCE / RETAIL SCAM DETECTION ===
    is_retail_scam_tld: bool = False         # .shop, .store, .sale, etc.
    is_ecommerce_site: bool = False          # Detected product listings/cart
    has_cross_domain_brand_link: bool = False # Links to same-brand different TLD
    cross_domain_brand_links: str = ""       # e.g., "gabyandbeauty.com" from gabyandbeauty.shop
    missing_business_identity: bool = False  # No legal name, address, registration
    business_identity_signals: str = ""      # What was found/missing
    
    # === APP STORE PRESENCE (Legitimacy Signal) ===
    app_store_has_presence: bool = False       # Any verified app store presence found
    app_store_confidence: str = ""             # none, low, medium, high
    app_store_ios_verified: bool = False       # Apple AASA deep link config found
    app_store_android_verified: bool = False   # Android Asset Links found
    app_store_page_links: bool = False         # App store links in page content
    app_store_itunes_match: bool = False       # iTunes API match found
    app_store_ios_app_ids: str = ""            # Semicolon-separated iOS app IDs
    app_store_android_packages: str = ""       # Semicolon-separated Android packages
    app_store_methods_found: str = ""          # Which detection methods found apps
    app_store_summary: str = ""                # Human-readable summary
    
    # === TLD VARIANT SPOOFING DETECTION ===
    tld_variant_detected: bool = False           # A TLD variant with established presence was found
    tld_variant_domain: str = ""                 # The established variant domain (e.g., "gordondown.co.uk")
    tld_variant_has_content: bool = False         # Variant has substantive website content
    tld_variant_has_email_infra: bool = False     # Variant has email auth configured (SPF/DKIM/MX)
    tld_variant_domain_age_days: int = -1         # Variant domain age in days
    tld_variant_content_words: int = 0            # Word count on variant's page
    tld_variant_signup_content_words: int = 0     # Word count on signup domain's page
    tld_variant_summary: str = ""                 # Human-readable summary of the comparison
    
    # === HOSTING PROVIDER DETECTION ===
    hosting_provider: str = ""                  # Detected provider name (e.g., "Hostinger", "GoDaddy")
    hosting_provider_type: str = ""             # budget_shared, free, suspect, premium, unknown
    hosting_detected_via: str = ""              # ns, asn, ptr, or combination
    hosting_asn: str = ""                       # ASN number if resolved
    hosting_asn_org: str = ""                   # ASN organization name
    blocked_asn_org_match: str = ""             # Matched blocked ASN org pattern (if any)
    
    # === HIGH-RISK COMPOSITE INDICATORS ===
    high_risk_phish_infra: bool = False          # Render ASN + self-hosted MX + both phish rules fired
    high_risk_phish_infra_reason: str = ""       # Human-readable explanation
    asn_display: str = ""                        # Formatted "AS{number} ({org})" for results display
    
    # === SCORING DETAILS ===
    signals_triggered: str = ""
    combos_triggered: str = ""
    rules_triggered: str = ""                    # Custom rules that fired (name:score pairs)
    rules_labels: str = ""                       # Human-readable labels for triggered rules
    score_breakdown: str = ""                    # JSON: {signal_or_rule: points} for every scored item
    
    # === VIRUSTOTAL REPUTATION ===
    vt_available: bool = False                   # True if VT API key was configured and query succeeded
    vt_malicious_count: int = 0                  # Vendors flagging domain as malicious
    vt_suspicious_count: int = 0                 # Vendors flagging domain as suspicious
    vt_total_vendors: int = 0                    # Total vendors that analyzed the domain
    vt_detection_rate: float = 0.0               # (malicious+suspicious) / total_vendors
    vt_community_score: int = 0                  # VT community votes (harmless - malicious)
    vt_reputation: int = 0                       # VT reputation score
    vt_threat_names: str = ""                    # Semicolon-separated threat family names
    vt_malicious_vendors: str = ""               # Semicolon-separated vendor names flagging malicious
    vt_categories: str = ""                      # JSON of vendor->category mappings
    vt_last_analysis: str = ""                   # Last VT analysis date
    
    # === HACKLINK / SEO SPAM DETECTION ===
    hacklink_detected: bool = False              # True if hacklink SEO spam injection detected
    hacklink_score: int = 0                      # Hacklink module risk score (0-30)
    hacklink_keywords: str = ""                  # Semicolon-separated hacklink keywords found
    hacklink_injection_patterns: str = ""        # Semicolon-separated injection patterns detected
    hacklink_is_wordpress: bool = False           # WordPress CMS detected
    hacklink_wp_compromised: bool = False         # WordPress compromise indicators found
    hacklink_vulnerable_plugins: str = ""         # Semicolon-separated vulnerable WP plugins
    hacklink_spam_link_count: int = 0            # Number of spam links found in content
    hacklink_malicious_script: bool = False       # SocGholish/FakeUpdates/obfuscated script injection
    hacklink_malicious_script_confidence: str = "" # HIGH, MEDIUM, or NONE — multi-signal confidence level
    hacklink_malicious_script_signals: str = ""    # Semicolon-separated signal names that fired
    hacklink_malicious_script_score: int = 0       # Accumulated multi-signal score
    hacklink_hidden_injection: bool = False       # CSS hidden content injection (display:none, font-size:0)
    hacklink_is_cpanel: bool = False              # cPanel hosting environment detected
    hacklink_suspicious_scripts: str = ""         # Semicolon-separated suspicious external script URLs
    
    # === WHOIS ENRICHMENT / TRANSFER LOCK ===
    whois_registrar: str = ""                    # Registrar name from WHOIS
    whois_updated: str = ""                      # WHOIS last-updated date (ISO)
    whois_statuses: str = ""                     # Semicolon-separated domain statuses
    domain_transfer_locked: bool = True          # clientTransferProhibited present (default True = safe)
    domain_transfer_lock_recent: bool = False    # Lock recently added on old domain (post-compromise lockdown signal)
    whois_recently_updated: bool = False         # WHOIS updated in last 30 days
    whois_recently_updated_days: int = -1        # Days since last WHOIS update
    
    # === EMPTY PAGE DETECTION ===
    is_empty_page: bool = False                  # Page returns empty or near-empty content (<50 chars)
    
    # === CERTIFICATE TRANSPARENCY ===
    ct_log_count: int = -1                       # Number of certs found in CT logs (-1 = not checked)
    ct_recent_issuance: bool = False             # Cert issued within last 7 days
    ct_issuers: str = ""                         # Semicolon-separated unique issuers
    ct_first_seen: str = ""                      # Earliest cert date in CT logs
    ct_last_seen: str = ""                       # Most recent cert date in CT logs


# ============================================================================
# CONSTANTS
# ============================================================================

DNS_TIMEOUT = 5.0
WEB_TIMEOUT = 8.0
MAX_REDIRECTS = 10

# DNSBL Rate Limit Protection (v6.2)
DNSBL_TIMEOUT = 5.0            # Timeout per DNSBL query (longer than general DNS)
DNSBL_RETRIES = 2              # Retries on timeout/SERVFAIL before marking inconclusive
DNSBL_RETRY_DELAY = 1.5        # Seconds between retries (backoff)
DNSBL_INTER_QUERY_DELAY = 0.3  # Seconds between consecutive DNSBL queries (rate limit)
DNSBL_CACHE_TTL = 300          # Cache results for 5 minutes

# In-memory DNSBL result cache: { "query:zone" -> (result, timestamp) }
# result: True = listed, False = clean, None = inconclusive
import time as _time
_dnsbl_cache: Dict[str, tuple] = {}

TEMP_REDIRECT_CODES = {302, 307}
PERM_REDIRECT_CODES = {301, 308, 303}
ALL_REDIRECT_CODES = TEMP_REDIRECT_CODES | PERM_REDIRECT_CODES

FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com',
]

FREE_HOSTING_PATTERNS = [
    'github.io', 'gitlab.io', 'pages.dev', 'netlify.app', 'vercel.app',
    'herokuapp.com', 'firebaseapp.com', 'azurewebsites.net',
    '000webhostapp.com', 'wixsite.com', 'weebly.com', 'blogspot.com',
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'j.mp', 'rb.gy', 'shorturl.at', 'cutt.ly',
]

PHISHING_PATHS = [
    '/signin', '/login', '/secure', '/verify', '/update', '/confirm',
    '/account', '/banking', '/webscr', '/paypal', '/amazon',
]

# ============================================================================
# PHISHING DOMAIN NAME PATTERNS (Tech Support Scam / Brand Impersonation)
# ============================================================================

# Suspicious prefixes commonly used in tech support scams
# Note: Some prefixes work with OR without hyphen (app-, app both suspicious)
SUSPICIOUS_PREFIXES_HYPHEN = [
    'app-', 'my-', 'get-', 'www-', 'login-', 'secure-', 'support-', 'help-',
    'account-', 'portal-', 'online-', 'web-', 'customer-', 'service-',
    'official-', 'verify-', 'update-', 'billing-', 'payment-',
    'i-download', 'download-', 'install-',
]

# These prefixes are suspicious even WITHOUT hyphen when followed by other text
# e.g., "appbelezia", "myaccount", "gethelp"
SUSPICIOUS_PREFIXES_NO_HYPHEN = [
    'app', 'my', 'get', 'login', 'secure', 'support', 'help',
    'account', 'portal', 'online', 'web', 'customer', 'service',
    'official', 'verify', 'update', 'billing', 'payment',
    'download', 'install', 'easy', 'howto', 'free', 'fast', 
    'quick', 'best', 'top',
]

# Legitimate words that start with suspicious prefixes - exclude from detection
# These should NOT trigger the prefix detection
LEGITIMATE_PREFIX_WORDS = [
    # Words starting with 'app'
    'apple', 'application', 'applications', 'appliance', 'appliances',
    'appetite', 'apparel', 'apparatus', 'appeal', 'appear', 'appearance',
    'appendix', 'applies', 'apply', 'appointment', 'appreciate', 'approach',
    'appropriate', 'approval', 'approve', 'approximate',
    # Words starting with 'my' - most are legitimate as "my" is a common word
    'myth', 'mystery', 'mysterious', 'myself', 'myriad',
    # Words starting with 'get'
    'getaway', 'getaways',
    # Words starting with 'top'
    'topic', 'topics', 'topical', 'topology', 'topography',
    # Words starting with 'best'
    'bestow', 'bestseller', 'bestsellers',
    # Words starting with 'free'
    'freedom', 'freelance', 'freelancer', 'freeway', 'freeze', 'freight',
    # Words starting with 'fast'
    'fasten', 'fastener', 'faster', 'fastest',
    # Words starting with 'quick'
    'quickly', 'quicken',
    # Words starting with 'easy'
    'easily', 'easier', 'easiest',
    # Words starting with 'web'
    'website', 'websites', 'webinar', 'webmaster',
    # Words starting with 'online'
    # (online + something is usually suspicious, keep it)
    # Words starting with 'secure'
    'security', 'securities', 'secured', 'securely',
    # Words starting with 'support'
    'supporter', 'supporters', 'supported', 'supporting', 'supportive',
    # Words starting with 'service'
    'services', 'serviced', 'servicer',
    # Words starting with 'account' (account is also a prefix we check)
    'accountant', 'accountants', 'accounting', 'accountable', 'accountability',
    # Words starting with 'customer'
    'customers', 'customary', 'customize', 'customized',
]

# Suspicious suffixes commonly used in tech support scams  
SUSPICIOUS_SUFFIXES = [
    'account', 'accounts', 'login', 'signin', 'support', 'help', 'helpdesk',
    'setup', 'install', 'download', 'update', 'upgrade', 'cancellation',
    'cancel', 'billing', 'payment', 'verify', 'verification', 'secure',
    'activate', 'activation', 'renew', 'renewal', 'subscription',
    'customer', 'service', 'official', 'online', 'portal', 'center',
    'assistant', 'desk', 'tech', 'fix', 'repair', 'cleaner', 'optimizer',
]

# Legitimate words that end with suspicious suffixes - exclude from detection
LEGITIMATE_SUFFIX_WORDS = [
    # Words ending with 'account'
    'accountant', 'accountancy', 'unaccountable', 'accountability',
    # Words ending with 'support'
    'supportive', 'unsupportive',
    # Words ending with 'service'
    'services', 'disservice',
    # Words ending with 'portal'
    # (most portal words are portal + modifier, keep detection)
    # Words ending with 'center'
    'epicenter', 'hypercenter',
    # Words ending with 'tech'
    'biotech', 'nanotech', 'hightech', 'lowtech', 'infotech',
    # Words ending with 'secure'
    'insecure',
    # Words ending with 'online'
    # (most are compound words like bankonline, keep detection)
]

# TLDs heavily abused for tech support scams
TECH_SUPPORT_SCAM_TLDS = [
    '.support', '.tech', '.help', '.services', '.solutions', '.center',
    '.expert', '.guru', '.pro', '.care', '.repair', '.fix',
]

# TLDs heavily abused for e-commerce/retail scams (fake stores, dropshipping scams)
RETAIL_SCAM_TLDS = [
    '.shop', '.store', '.sale', '.deals', '.bargains', '.discount', '.cheap',
    '.buy', '.shopping', '.market', '.boutique', '.fashion', '.shoes',
    '.jewelry', '.watch', '.gifts', '.flowers', '.furniture', '.toys',
]

# E-commerce indicators in page content
ECOMMERCE_INDICATORS = [
    'add to cart', 'add to bag', 'buy now', 'shop now', 'checkout',
    'shopping cart', 'your cart', 'view cart', 'price', 'order now',
    'free shipping', 'fast delivery', 'product description', 'quantity',
    'in stock', 'out of stock', 'add to wishlist', 'save for later',
]

# Business identity indicators (what legitimate businesses show)
BUSINESS_IDENTITY_PATTERNS = [
    # Legal entity identifiers
    r'\b(inc|llc|ltd|corp|corporation|gmbh|sarl|bv|ag|co\.)\b',
    # Registration numbers
    r'\b(registration|reg\.?\s*no|business\s*number|company\s*number|ein|vat|abn)\s*[:.\s]*[\w\d-]+',
    # Physical address indicators
    r'\b\d+\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln)\b',
    r'\b(suite|ste|floor|unit|building)\s*[#\d]+',
    # Contact legitimacy
    r'\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}',  # Phone numbers
]

# Expanded brand list for domain-name impersonation detection
# Includes: ISPs, security software, streaming, tech companies, utilities,
# airlines, travel, shipping, financial services, e-commerce
IMPERSONATED_BRANDS = [
    # Major tech companies (already in content check)
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix',
    
    # ISPs / Email providers (common tech support scam targets)
    'aol', 'att', 'bellsouth', 'centurylink', 'charter', 'comcast', 'cox',
    'earthlink', 'frontier', 'hughesnet', 'juno', 'mediacom', 'optimum',
    'roadrunner', 'spectrum', 'suddenlink', 'verizon', 'windstream', 'xfinity',
    'yahoo', 'gmail', 'outlook', 'hotmail', 'protonmail', 'startmail',
    'duckduckgo', 'prontoemail', 'prontomail',
    
    # Security software (huge tech support scam target)
    'norton', 'mcafee', 'avast', 'avg', 'bitdefender', 'kaspersky', 'malwarebytes',
    'webroot', 'trendmicro', 'sophos', 'eset', 'avira', 'pcmatic', 'totalav',
    'scanguard', 'stopzilla', 'hitmanpro', 'spyhunter', 'fixmestick',
    'cleanmymac', 'macpaw', 'ccleaner', 'iolo', 'systemcare',
    
    # Streaming services
    'hulu', 'disney', 'hbomax', 'peacock', 'paramount', 'fubo', 'fubotv',
    'sling', 'vudu', 'roku', 'appletv', 'primevideo', 'spotify', 'pandora',
    
    # Hardware / Printers (tech support scam targets)
    'hp', 'canon', 'epson', 'brother', 'lexmark', 'dymo', 'xerox', 'dell',
    'lenovo', 'asus', 'acer', 'toshiba', 'samsung', 'logitech',
    
    # Software
    'quickbooks', 'turbotax', 'quicken', 'sage', 'adobe', 'autodesk',
    'dropbox', 'carbonite', 'idrive', 'backblaze', 'crashplan',
    
    # Gaming / Entertainment
    'pogo', 'steam', 'epic', 'origin', 'ubisoft', 'blizzard', 'roblox',
    
    # Other commonly impersonated
    'geeksquad', 'bestbuy', 'costco', 'walmart', 'target',
    
    # === Airlines (high-value phishing targets — booking/payment data) ===
    'easyjet', 'ryanair', 'british airways', 'britishairways', 'emirates',
    'lufthansa', 'airfrance', 'klm', 'southwest', 'southwestairlines',
    'delta', 'united', 'american airlines', 'americanairlines',
    'jetblue', 'spirit', 'frontier airlines', 'allegiant', 'alaska airlines',
    'wizzair', 'vueling', 'eurowings', 'norwegian', 'tui', 'jet2',
    'qantas', 'virgin atlantic', 'virginatlantic', 'aer lingus', 'aerlingus',
    'turkish airlines', 'turkishairlines', 'cathay pacific', 'cathaypacific',
    'singapore airlines', 'singaporeairlines', 'etihad', 'qatar airways',
    'qatarairways', 'airindia',
    
    # === Travel / Booking (phishing targets — payment/personal data) ===
    'booking', 'expedia', 'airbnb', 'tripadvisor', 'hotels', 'trivago',
    'kayak', 'skyscanner', 'priceline', 'orbitz', 'travelocity',
    'lastminute', 'trainline', 'eurostar', 'flixbus',
    
    # === Shipping / Logistics (delivery phishing — customs fees, tracking) ===
    'fedex', 'usps', 'ups', 'dhl', 'royalmail', 'hermes', 'evri',
    'yodel', 'dpd', 'parcelforce', 'postnl', 'laposte', 'correos',
    'deutschepost', 'aramex', 'maersk',
    
    # === Banks / Financial (high-value: account access, payments) ===
    'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'hsbc',
    'barclays', 'lloyds', 'natwest', 'santander', 'halifax',
    'nationwide', 'tsb', 'monzo', 'revolut', 'starling',
    'capitalone', 'americanexpress', 'amex', 'discover',
    'goldmansachs', 'morganstanley', 'schwab', 'fidelity', 'vanguard',
    'robinhood', 'coinbase', 'binance', 'kraken', 'blockchain', 'metamask',
    
    # === Payment / Fintech ===
    'stripe', 'square', 'venmo', 'zelle', 'cashapp', 'wise', 'transferwise',
    'klarna', 'afterpay', 'affirm', 'clearpay',
    
    # === E-commerce / Retail ===
    'ebay', 'alibaba', 'aliexpress', 'etsy', 'shopify', 'wish',
    'wayfair', 'asos', 'zara', 'shein', 'temu',
    
    # === Telecoms ===
    'vodafone', 'tmobile', 'sprint', 'three', 'orange', 'telefonica',
    'bt', 'ee', 'o2', 'giffgaff', 'sky', 'virgin media', 'virginmedia',
    
    # === Government / Tax (seasonal phishing spikes) ===
    'hmrc', 'irs', 'dvla', 'govuk',
]

# ============================================================================
# BRAND SPOOFING KEYWORDS
# ============================================================================
# When a known brand name appears in a domain COMBINED with one of these
# keywords, the risk is significantly higher. These keywords mimic legitimate
# brand services/portals (easyjetconnect.com, amazonverify.com, etc.)
#
# Scored as a separate signal on top of domain_brand_impersonation.
# ============================================================================

BRAND_SPOOFING_KEYWORDS = [
    # Connection / Access
    'connect', 'connected', 'connection', 'linking', 'link',
    # Authentication / Verification
    'login', 'logon', 'signin', 'signup', 'signon',
    'verify', 'verification', 'validate', 'confirm', 'auth',
    # Account / Portal
    'account', 'accounts', 'myaccount', 'portal', 'dashboard',
    'member', 'members', 'membership', 'profile', 'user',
    # Security / Trust
    'secure', 'security', 'safe', 'protect', 'protection', 'shield',
    'trust', 'trusted', 'official', 'verified',
    # Support / Service
    'support', 'helpdesk', 'help', 'service', 'services', 'care',
    'customer', 'contact', 'assist', 'center', 'centre',
    # Updates / Billing
    'update', 'upgrade', 'renew', 'renewal', 'billing', 'payment',
    'pay', 'invoice', 'refund', 'claim', 'reward', 'rewards',
    # Tracking / Delivery (shipping brand phishing)
    'track', 'tracking', 'deliver', 'delivery', 'parcel', 'package',
    'shipment', 'shipping', 'dispatch', 'customs', 'collect',
    # Booking / Travel (airline/travel brand phishing)
    'book', 'booking', 'bookings', 'reserve', 'reservation',
    'flight', 'flights', 'checkin', 'boardingpass', 'itinerary',
    # Notifications / Communication
    'notify', 'notification', 'notifications', 'alert', 'alerts',
    'message', 'messages', 'inbox', 'mail', 'email',
    # Management / Admin
    'manage', 'manager', 'admin', 'panel', 'control',
    # App / Digital
    'app', 'apps', 'online', 'web', 'digital', 'cloud',
    # Action / Download
    'download', 'install', 'setup', 'activate', 'activation',
    # Status
    'status', 'info', 'information', 'notice', 'advisory',
]

# Content-based brand detection (for page content scanning)
# NOTE: 'apple' removed — triggers on every site with apple-touch-icon/
# apple-mobile-web-app-capable meta tags. Apple phishing is caught by
# typosquatting, domain name patterns, credential forms, and phishing paths.
BRAND_KEYWORDS = [
    b'paypal', b'amazon', b'microsoft', b'google', b'facebook',
    b'instagram', b'netflix', b'bank of america', b'chase', b'wells fargo',
    b'usps', b'fedex', b'dropbox', b'docusign',
]

# Short keywords that need word boundary matching (to avoid false positives like "first" matching "irs")
BRAND_KEYWORDS_SHORT = [b'irs', b'ups', b'dhl']

CREDENTIAL_PATTERNS = [b'type="password"', b"type='password'", b'name="password"']
SENSITIVE_PATTERNS = [b'name="ssn"', b'name="card_number"', b'name="cvv"']
JS_REDIRECT_PATTERNS = [b'location.href', b'location.replace', b'window.location']
MALWARE_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.msi', '.jar', '.vbs', '.apk']

# ============================================================================
# HIJACKED DOMAIN / STEPPING STONE DETECTION PATTERNS
# Based on research: https://keepaware.com/blog/over-100-domains-hijacked
# ============================================================================

# Suspicious URL path segments (phishing pages hidden in subdirectories)
HIJACK_PATH_KEYWORDS = [
    'tunnel', 'bid', 'invite', 'secure', 'memo', 'document', 'fileshare',
    'agreement', 'policy', 'scan', 'rfp', 'proposal', 'submission',
    'sharedsuccess', 'teamwork', 'workers-team', 'team-work', 'team-admin',
    'autodocs', 'onlstorage', 'tunelstorage', 'cstorefile', 'archiev',
    'proceed', 'record', 'source', 'incoming-bid', 'drive', 'zoom',
    'invitation', 'offers', 'master', 'project', 'realestate', 'legal',
]

# Suspicious filename patterns in URLs
HIJACK_FILE_PATTERNS = [
    'email-template.html', 'proposal.html', 'policy.html', 'home.html',
    'index.html', 'scan.html', 'agreement.html', 'project.html',
    'compliance.html', 'secure.html', 'form.html', 'preview-form.html',
]

# Known phishing infrastructure domains (redirects to these = bad)
PHISHING_INFRASTRUCTURE = [
    'workers.dev',           # Cloudflare workers - heavily abused
    'pages.dev',             # Cloudflare pages
    'netlify.app',           # Netlify - abused for phishing
    'vercel.app',            # Vercel - abused
    'herokuapp.com',         # Heroku
    'glitch.me',             # Glitch
    'replit.dev',            # Replit
    'web.app',               # Firebase
    'firebaseapp.com',       # Firebase
    'azurewebsites.net',     # Azure (often abused)
    'blob.core.windows.net', # Azure blob storage
    'googleapis.com',        # Google APIs (sometimes abused)
    'ipfs.io',               # IPFS - decentralized, hard to takedown
    'dweb.link',             # IPFS gateway
    'fleek.co',              # IPFS hosting
    'arweave.net',           # Permanent storage - abused
]

# Document sharing lure patterns (in page content)
DOC_SHARING_LURES = [
    b'secure document sharing',
    b'business document shared',
    b'shared document',
    b'view document',
    b'access document',
    b'download document',
    b'open document',
    b'document preview',
    b'file shared with you',
    b'has shared a file',
    b'sent you a document',
    b'review document',
    b'sign document',
    b'confidential document',
    b'important document',
    b'urgent document',
    b'invoice attached',
    b'payment document',
    b'enter your email to view',
    b'verify your email to access',
    b'enter email to continue',
]

# JavaScript patterns indicating phishing kit behavior
PHISHING_JS_PATTERNS = [
    b'atob(',                          # Base64 decoding (URL obfuscation)
    b'window.location.hash',           # Email extraction from URL hash
    b'getEmailFromHash',               # Function name from known kits
    b'decodeBase64',                   # Base64 decoding function
    b'loadingOverlay',                 # Fake loading screen
    b'loadingSpinner',                 # Fake loading spinner
    b"btoa(",                          # Base64 encoding
    b'.workers.dev',                   # Cloudflare workers redirect
    b'captchaResponse',                # Fake captcha
    b'validate-captcha.php',           # Fake captcha validation
    b'redirectUrl',                    # Redirect configuration
    b'emailFromHash',                  # Email from URL hash
]


# ============================================================================
# DNS FUNCTIONS
# ============================================================================

def dns_query(domain: str, record_type: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        return [str(rdata) for rdata in resolver.resolve(domain, record_type)]
    except Exception:
        return []


def get_ptr_record(ip: str) -> Tuple[bool, str, bool]:
    if not DNS_AVAILABLE or not ip:
        return False, "", False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        if not answers:
            return False, "", False
        ptr_hostname = str(answers[0]).rstrip('.')
        try:
            forward_ips = [str(r) for r in resolver.resolve(ptr_hostname, 'A')]
            matches = ip in forward_ips
        except Exception:
            matches = False
        return True, ptr_hostname, matches
    except Exception:
        return False, "", False


def get_spf(domain: str) -> Tuple[str, bool, Dict]:
    for record in dns_query(domain, 'TXT'):
        record = record.strip('"').strip("'")
        if record.lower().startswith('v=spf1'):
            return record, True, parse_spf(record)
    return "", False, {}


def parse_spf(spf: str) -> Dict:
    result = {"mechanism": "", "includes": [], "lookups": 0, "valid": True, "permissive": False}
    spf_lower = spf.lower()
    all_match = re.search(r'([+\-~?]?)all\b', spf_lower)
    if all_match:
        q = all_match.group(1) or '+'
        result["mechanism"] = f"{q}all"
        if q in ['+', '?']:
            result["permissive"] = True
    for m in ['include:', 'a:', 'mx:', 'ptr:', 'exists:', 'redirect=']:
        result["lookups"] += spf_lower.count(m)
    result["includes"] = re.findall(r'include:([^\s]+)', spf_lower)
    if not spf_lower.startswith('v=spf1'):
        result["valid"] = False
    return result


def get_dmarc(domain: str) -> Tuple[str, bool, Dict]:
    for record in dns_query(f"_dmarc.{domain}", 'TXT'):
        record = record.strip('"').strip("'")
        if record.lower().startswith('v=dmarc1'):
            return record, True, parse_dmarc(record)
    return "", False, {}


def parse_dmarc(dmarc: str) -> Dict:
    result = {"policy": "", "pct": 100, "rua": "", "valid": True}
    dmarc_lower = dmarc.lower()
    p = re.search(r'\bp=(\w+)', dmarc_lower)
    if p:
        result["policy"] = p.group(1)
    pct = re.search(r'\bpct=(\d+)', dmarc_lower)
    if pct:
        result["pct"] = int(pct.group(1))
    rua = re.search(r'\brua=([^;\s]+)', dmarc_lower)
    if rua:
        result["rua"] = rua.group(1)
    if not result["policy"]:
        result["valid"] = False
    return result


def check_dkim(domain: str) -> Tuple[bool, List[str]]:
    selectors = ['default', 'dkim', 'selector1', 'selector2', 'google', 'k1', 's1', 's2', 
                 'mandrill', 'everlytickey1', 'everlytickey2', 'dkim1', 'dkim2', 'mail',
                 'smtp', 'email', 'key1', 'key2', 'selector', 'sendgrid', 'amazonses']
    found = []
    for sel in selectors:
        records = dns_query(f"{sel}._domainkey.{domain}", 'TXT')
        for r in records:
            if 'v=dkim1' in r.lower() or 'p=' in r.lower():
                found.append(sel)
                break
        if len(found) >= 3:
            break
    return len(found) > 0, found


def get_mx(domain: str) -> Tuple[bool, List[Tuple[int, str]], bool]:
    if not DNS_AVAILABLE:
        return False, [], False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'MX')
        mx = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        is_null = len(mx) == 1 and mx[0][0] == 0 and mx[0][1] in ['', '.']
        return True, mx, is_null
    except Exception:
        return False, [], False


def classify_mx_provider(mx_records: List[Tuple[int, str]], domain: str, config: dict) -> str:
    """Classify MX provider type based on MX hostnames.
    
    Returns: 'enterprise', 'standard', 'disposable', 'selfhosted', or 'unknown'
    """
    if not mx_records:
        return "unknown"
    
    mx_providers = config.get('mx_providers', {})
    
    # Check all MX hostnames (primary first, but check all)
    all_mx_hosts = [h.lower() for _, h in mx_records]
    
    # Check enterprise patterns first (highest priority)
    enterprise_patterns = mx_providers.get('enterprise', {}).get('patterns', [])
    for mx_host in all_mx_hosts:
        for pattern in enterprise_patterns:
            if pattern.lower() in mx_host:
                return "enterprise"
    
    # Check standard patterns
    standard_patterns = mx_providers.get('standard', {}).get('patterns', [])
    for mx_host in all_mx_hosts:
        for pattern in standard_patterns:
            if pattern.lower() in mx_host:
                return "standard"
    
    # Check disposable patterns
    disposable_patterns = mx_providers.get('disposable', {}).get('patterns', [])
    for mx_host in all_mx_hosts:
        for pattern in disposable_patterns:
            if pattern.lower() in mx_host:
                return "disposable"
    
    # Check if self-hosted (MX points to same domain or subdomain)
    domain_lower = domain.lower()
    for mx_host in all_mx_hosts:
        if mx_host == domain_lower or mx_host.endswith('.' + domain_lower):
            return "selfhosted"
    
    return "unknown"


def get_bimi(domain: str) -> Tuple[bool, str]:
    for record in dns_query(f"default._bimi.{domain}", 'TXT'):
        record = record.strip('"').strip("'")
        if record.lower().startswith('v=bimi1'):
            return True, record[:200]
    return False, ""


def get_mta_sts(domain: str) -> Tuple[bool, str]:
    for record in dns_query(f"_mta-sts.{domain}", 'TXT'):
        record = record.strip('"').strip("'")
        if 'v=sts' in record.lower():
            return True, record[:200]
    return False, ""


def check_blacklist(query: str, zone: str) -> Optional[bool]:
    """
    Check if query is listed in a DNSBL zone.
    
    v6.2: Now distinguishes between "not listed" and "check failed".
    
    Returns:
        True  = listed (DNSBL returned a result)
        False = NOT listed (NXDOMAIN — definitive clean)
        None  = INCONCLUSIVE (timeout, SERVFAIL, rate limited — we don't know)
    """
    if not DNS_AVAILABLE:
        return None  # Can't check = inconclusive, NOT clean
    
    cache_key = f"{query}:{zone}"
    
    # Check cache first (v6.2)
    if cache_key in _dnsbl_cache:
        cached_result, cached_time = _dnsbl_cache[cache_key]
        if _time.time() - cached_time < DNSBL_CACHE_TTL:
            return cached_result
        else:
            del _dnsbl_cache[cache_key]  # Expired
    
    result = None  # Default: inconclusive
    
    for attempt in range(1 + DNSBL_RETRIES):
        if attempt > 0:
            _time.sleep(DNSBL_RETRY_DELAY)  # Backoff between retries
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNSBL_TIMEOUT
            resolver.lifetime = DNSBL_TIMEOUT
            resolver.resolve(f"{query}.{zone}", 'A')
            result = True  # Listed
            break
            
        except dns.resolver.NXDOMAIN:
            # Definitive: domain is NOT on this blacklist
            result = False
            break
            
        except dns.resolver.NoAnswer:
            # Zone exists but no A record — treat as not listed
            result = False
            break
            
        except dns.resolver.NoNameservers:
            # SERVFAIL / all nameservers failed — likely rate limited
            continue  # Retry
            
        except dns.exception.Timeout:
            # Timeout — likely rate limited or network issue
            continue  # Retry
            
        except Exception:
            # Other DNS errors — inconclusive
            continue  # Retry
    
    # Cache the result (even inconclusive, to avoid hammering a broken zone)
    _dnsbl_cache[cache_key] = (result, _time.time())
    
    return result


def check_domain_blacklists(domain: str, blacklists: List[str]) -> Tuple[List[str], int, int]:
    """
    Check domain against all configured DNSBL zones.
    
    v6.2: Now returns inconclusive count as third element.
    
    Returns: (hits, hit_count, inconclusive_count)
    """
    hits = []
    inconclusive = 0
    
    for bl in blacklists:
        result = check_blacklist(domain, bl)
        if result is True:
            hits.append(bl)
        elif result is None:
            inconclusive += 1
        # False = clean, nothing to track
        
        # Rate limit: pause between queries to avoid triggering DNSBL limits
        if bl != blacklists[-1]:  # Don't sleep after last query
            _time.sleep(DNSBL_INTER_QUERY_DELAY)
    
    return hits, len(hits), inconclusive


def check_ip_blacklists(ip: str, blacklists: List[str]) -> Tuple[List[str], int, int]:
    """
    Check IP against all configured RBL zones.
    
    v6.2: Now returns inconclusive count as third element.
    
    Returns: (hits, hit_count, inconclusive_count)
    """
    if not ip:
        return [], 0, 0
    reversed_ip = '.'.join(reversed(ip.split('.')))
    hits = []
    inconclusive = 0
    
    for bl in blacklists:
        result = check_blacklist(reversed_ip, bl)
        if result is True:
            hits.append(bl)
        elif result is None:
            inconclusive += 1
        
        if bl != blacklists[-1]:
            _time.sleep(DNSBL_INTER_QUERY_DELAY)
    
    return hits, len(hits), inconclusive


# ============================================================================
# HOSTING PROVIDER DETECTION
# ============================================================================

def get_asn_info(ip: str) -> Tuple[str, str]:
    """
    Look up ASN number and organization for an IP via Team Cymru DNS.
    
    Query: reversed_ip.origin.asn.cymru.com → TXT record
    Response format: "ASN | IP/CIDR | CC | Registry | Date"
    Then: AS<number>.asn.cymru.com → TXT record for org name
    
    Returns: (asn_number, asn_org_name) or ("", "") on failure
    """
    if not DNS_AVAILABLE or not ip:
        return "", ""
    
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        
        # Step 1: Get ASN number from IP
        answers = resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", 'TXT')
        if not answers:
            return "", ""
        
        txt = str(answers[0]).strip('"').strip("'")
        parts = [p.strip() for p in txt.split('|')]
        if not parts:
            return "", ""
        
        asn_number = parts[0].strip()
        if not asn_number:
            return "", ""
        
        # Step 2: Get org name from ASN
        try:
            org_answers = resolver.resolve(f"AS{asn_number}.asn.cymru.com", 'TXT')
            if org_answers:
                org_txt = str(org_answers[0]).strip('"').strip("'")
                org_parts = [p.strip() for p in org_txt.split('|')]
                # Org name is the last field
                asn_org = org_parts[-1].strip() if len(org_parts) >= 5 else ""
                return asn_number, asn_org
        except Exception:
            pass
        
        return asn_number, ""
    except Exception:
        return "", ""


def check_hosting_provider(domain: str, ip: str, ns_records: List[str] = None, 
                           ptr_record: str = "", hosting_config: dict = None) -> Dict:
    """
    Detect hosting provider using multiple signals:
    1. Nameserver patterns (most hosts use branded NS)
    2. ASN lookup (network owner identification)
    3. PTR record patterns (reverse DNS often shows host)
    
    Returns dict with provider info and risk tier.
    """
    result = {
        "provider": "",
        "provider_type": "",      # budget_shared, free, suspect, premium, unknown
        "detected_via": "",       # ns, asn, ptr
        "asn": "",
        "asn_org": "",
        "match_details": [],      # What matched and how
    }
    
    if not hosting_config:
        hosting_config = {}
    
    providers = hosting_config.get("hosting_providers", {})
    if not providers:
        return result
    
    # Collect NS records if not provided
    if ns_records is None:
        ns_records = dns_query(domain, 'NS')
    
    ns_lower = [ns.lower().rstrip('.') for ns in ns_records]
    ptr_lower = ptr_record.lower() if ptr_record else ""
    
    # Get ASN info
    asn_number, asn_org = get_asn_info(ip)
    result["asn"] = asn_number
    result["asn_org"] = asn_org
    asn_org_lower = asn_org.lower()
    
    best_match = None
    best_priority = 999  # Lower = better match
    
    for provider_key, provider_def in providers.items():
        matched = False
        match_method = ""
        
        # Check NS patterns (priority 1 - most reliable)
        ns_patterns = provider_def.get("ns_patterns", [])
        for pattern in ns_patterns:
            pattern_lower = pattern.lower()
            for ns in ns_lower:
                if pattern_lower in ns:
                    matched = True
                    match_method = "ns"
                    break
            if matched:
                break
        
        # Check ASN numbers (priority 2 - very reliable)
        if not matched:
            asn_numbers = provider_def.get("asn_numbers", [])
            if asn_number and asn_number in [str(a) for a in asn_numbers]:
                matched = True
                match_method = "asn"
        
        # Check ASN org name patterns (priority 3 - reliable)
        if not matched:
            asn_patterns = provider_def.get("asn_org_patterns", [])
            for pattern in asn_patterns:
                if pattern.lower() in asn_org_lower:
                    matched = True
                    match_method = "asn_org"
                    break
        
        # Check PTR patterns (priority 4 - good but can be changed)
        if not matched and ptr_lower:
            ptr_patterns = provider_def.get("ptr_patterns", [])
            for pattern in ptr_patterns:
                if pattern.lower() in ptr_lower:
                    matched = True
                    match_method = "ptr"
                    break
        
        if matched:
            # Determine priority (ns > asn > ptr)
            priority_map = {"ns": 1, "asn": 2, "asn_org": 3, "ptr": 4}
            priority = priority_map.get(match_method, 5)
            
            if priority < best_priority:
                best_priority = priority
                best_match = {
                    "provider": provider_def.get("name", provider_key),
                    "provider_type": provider_def.get("type", "unknown"),
                    "detected_via": match_method,
                    "key": provider_key,
                }
    
    if best_match:
        result["provider"] = best_match["provider"]
        result["provider_type"] = best_match["provider_type"]
        result["detected_via"] = best_match["detected_via"]
    
    return result


# ============================================================================
# TYPOSQUATTING DETECTION
# ============================================================================

def check_typosquatting(domain: str, protected_brands: List[str]) -> Tuple[str, float]:
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    tld = parts[-1] if parts else ""
    brand_like_tlds = {'app', 'shop', 'store', 'bank', 'pay', 'mail', 'cloud', 'tech'}
    
    if len(parts) >= 2:
        main_part = parts[-2]
    else:
        main_part = parts[0]
    
    if len(main_part) < 4:
        return "", 0.0
    
    def normalize(s: str) -> str:
        s = s.replace('-', '').replace('_', '')
        s = s.replace('0', 'o').replace('1', 'l').replace('3', 'e')
        s = s.replace('4', 'a').replace('5', 's').replace('@', 'a')
        return s
    
    normalized_main = normalize(main_part)
    best_match = ""
    best_score = 0.0
    
    for brand in protected_brands:
        if domain_lower == f"{brand}.com" or domain_lower == f"{brand}.net" or domain_lower == f"{brand}.org":
            continue
        if tld in brand_like_tlds:
            tld_brand_similarity = difflib.SequenceMatcher(None, tld, brand).ratio()
            if tld_brand_similarity >= 0.6:
                continue
        if len(brand) <= 3:
            continue
        
        scores = []
        base_ratio = difflib.SequenceMatcher(None, main_part, brand).ratio()
        normalized_ratio = difflib.SequenceMatcher(None, normalized_main, brand).ratio()
        
        if base_ratio >= 0.75:
            scores.append(base_ratio)
        if normalized_ratio >= 0.75:
            scores.append(normalized_ratio)
        
        if brand in main_part and main_part != brand and len(main_part) >= len(brand) + 2:
            scores.append(0.85)
        if brand in normalized_main and normalized_main != brand and len(normalized_main) >= len(brand) + 2:
            scores.append(0.80)
        
        if len(brand) >= 5:
            for i in range(len(brand)):
                truncated = brand[:i] + brand[i+1:]
                if main_part == truncated or normalized_main == truncated:
                    scores.append(0.90)
        
        if len(main_part) == len(brand) + 1 and len(brand) >= 4:
            for i in range(len(main_part)):
                reduced = main_part[:i] + main_part[i+1:]
                if reduced == brand:
                    scores.append(0.88)
        
        if len(main_part) == len(brand) and len(brand) >= 5:
            diffs = sum(1 for a, b in zip(main_part, brand) if a != b)
            if diffs == 2:
                scores.append(0.85)
        
        max_score = max(scores) if scores else 0.0
        if max_score > best_score and max_score >= 0.78:
            best_score = max_score
            best_match = brand
    
    return best_match, best_score


def is_disposable_email(domain: str, disposable_list: List[str]) -> bool:
    domain_lower = domain.lower()
    if domain_lower in disposable_list:
        return True
    for disp in disposable_list:
        if domain_lower.endswith('.' + disp):
            return True
    disposable_patterns = [
        r'^temp.*mail', r'^fake.*mail', r'^trash.*mail', r'^throw.*mail',
        r'^disposable', r'^temporary.*email', r'^10minute', r'^guerrilla',
    ]
    for pattern in disposable_patterns:
        if re.search(pattern, domain_lower):
            return True
    return False


def check_domain_name_patterns(domain: str, config: dict = None) -> Dict:
    """
    Detect tech support scam / brand impersonation patterns in domain name.
    
    Patterns detected:
    1. Suspicious prefixes: app-, my-, get-, support-, login-, etc.
    2. Suspicious suffixes: account, setup, cancellation, support, etc.
    3. Tech support scam TLDs: .support, .tech, .help, etc.
    4. Brand names embedded in domain: spectrum, verizon, norton, etc.
    5. Brand + spoofing keyword: easyjetconnect, amazonverify, etc. (v5.2)
    
    Returns dict with detection results.
    """
    result = {
        "has_suspicious_prefix": False,
        "suspicious_prefix": "",
        "has_suspicious_suffix": False, 
        "suspicious_suffix": "",
        "is_tech_support_tld": False,
        "domain_impersonates_brand": "",
        "brand_spoofing_keyword": "",
        "brand_plus_keyword": False,
        "patterns_found": [],
        "risk_score_addition": 0,
    }
    
    domain_lower = domain.lower().strip()
    
    # Extract main part (without TLD)
    parts = domain_lower.rsplit('.', 1)
    if len(parts) == 2:
        main_part = parts[0]
        tld = '.' + parts[1]
    else:
        main_part = domain_lower
        tld = ""
    
    # Check for multi-part TLDs like .co.uk
    full_tld = ""
    for tst in TECH_SUPPORT_SCAM_TLDS:
        if domain_lower.endswith(tst):
            full_tld = tst
            main_part = domain_lower[:-len(tst)]
            break
    
    # Normalize: remove hyphens for brand matching
    normalized = main_part.replace('-', '').replace('_', '')
    
    # === CHECK 1: Suspicious prefixes ===
    # First check hyphenated prefixes (e.g., "app-spectrum")
    for prefix in SUSPICIOUS_PREFIXES_HYPHEN:
        if main_part.startswith(prefix):
            result["has_suspicious_prefix"] = True
            result["suspicious_prefix"] = prefix
            result["patterns_found"].append(f"prefix:{prefix}")
            result["risk_score_addition"] += 12
            break
    
    # Then check non-hyphenated prefixes (e.g., "appbelezia", "myaccount")
    # Only if we haven't already found a hyphenated prefix
    if not result["has_suspicious_prefix"]:
        for prefix in SUSPICIOUS_PREFIXES_NO_HYPHEN:
            # Must start with prefix AND have more characters after
            if main_part.startswith(prefix) and len(main_part) > len(prefix):
                # Avoid false positives: check if this is a legitimate word
                if main_part in LEGITIMATE_PREFIX_WORDS:
                    continue
                    
                # Avoid false positives: make sure it's not just the prefix as the whole name
                # e.g., "app.com" alone shouldn't flag, but "appbelezia.com" should
                remaining = main_part[len(prefix):]
                # The remaining part should look like it could be a word/brand
                if len(remaining) >= 3 and remaining[0].isalpha():
                    result["has_suspicious_prefix"] = True
                    result["suspicious_prefix"] = prefix
                    result["patterns_found"].append(f"prefix:{prefix}")
                    result["risk_score_addition"] += 12
                    break
    
    # === CHECK 2: Suspicious suffixes ===
    for suffix in SUSPICIOUS_SUFFIXES:
        # Check if domain ends with suffix (e.g., "spectrumaccount" ends with "account")
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            # Avoid false positives: check if this is a legitimate word
            if normalized in LEGITIMATE_SUFFIX_WORDS:
                continue
            result["has_suspicious_suffix"] = True
            result["suspicious_suffix"] = suffix
            result["patterns_found"].append(f"suffix:{suffix}")
            result["risk_score_addition"] += 12
            break
    
    # === CHECK 3: Tech support scam TLDs ===
    if full_tld:
        result["is_tech_support_tld"] = True
        result["patterns_found"].append(f"tld:{full_tld}")
        result["risk_score_addition"] += 15
    else:
        for scam_tld in TECH_SUPPORT_SCAM_TLDS:
            if domain_lower.endswith(scam_tld):
                result["is_tech_support_tld"] = True
                result["patterns_found"].append(f"tld:{scam_tld}")
                result["risk_score_addition"] += 15
                break
    
    # === CHECK 4: Brand impersonation in domain name ===
    # This catches domains like "app-spectrum.com", "nortonaccount.com"
    # 
    # v5.x improvements:
    #   - Word-boundary matching for short brands (avoids "first" → "irs")
    #   - Minimum brand-to-domain ratio (avoids tiny brand in long domain)
    #   - Allowlist of common English words that contain brand substrings
    matched_brand = ""
    matched_brand_normalized = ""
    
    # Load brand impersonation tuning from config (with sensible defaults)
    brand_config = config.get("brand_impersonation", {}) if config else {}
    short_brand_max_len = brand_config.get("short_brand_max_len", 5)
    brand_min_domain_ratio = brand_config.get("brand_min_domain_ratio", 0.25)
    brand_allowlist_words = [w.lower() for w in brand_config.get("brand_allowlist_words", [])]
    
    for brand in IMPERSONATED_BRANDS:
        brand_normalized = brand.replace(' ', '').lower()
        
        # Skip very short brands that cause false positives (2-char: hp, bt, ee, o2)
        if len(brand_normalized) < 3:
            continue
            
        # Check if brand is in the domain (but domain is not the exact brand)
        if brand_normalized in normalized:
            # Make sure it's not the legitimate domain
            legitimate = [f"{brand_normalized}.com", f"{brand_normalized}.net", 
                         f"{brand_normalized}.org", f"{brand_normalized}.co",
                         f"{brand_normalized}.co.uk", f"{brand_normalized}.com.au",
                         f"{brand_normalized}.eu", f"{brand_normalized}.de",
                         f"{brand_normalized}.fr", f"{brand_normalized}.io"]
            if domain_lower not in legitimate:
                # Make sure the domain isn't just a longer legit name
                # e.g., "spectrum.net" vs "spectrumaccount.com"
                if normalized != brand_normalized:
                    
                    brand_pos = normalized.find(brand_normalized)
                    brand_end = brand_pos + len(brand_normalized)
                    at_start = (brand_pos == 0)
                    at_end = (brand_end == len(normalized))
                    
                    # Check if brand appears at a hyphen boundary in the original domain
                    at_hyphen_boundary = False
                    segments = main_part.split('-')
                    for seg in segments:
                        seg_clean = seg.replace('_', '')
                        if seg_clean == brand_normalized:
                            at_hyphen_boundary = True
                            break
                        if seg_clean.startswith(brand_normalized) or seg_clean.endswith(brand_normalized):
                            if len(seg_clean) == len(brand_normalized):
                                at_hyphen_boundary = True
                                break
                    
                    is_at_boundary = at_start or at_end or at_hyphen_boundary
                    
                    # --- NEW: Word-boundary check for short brands ---
                    # Short brands (≤ short_brand_max_len chars) must appear at a
                    # word boundary: start/end of domain part, or adjacent to a
                    # hyphen in the original (un-normalized) domain.
                    # This prevents "first" → "irs", "birdsong" → "irs", etc.
                    if len(brand_normalized) <= short_brand_max_len:
                        if not is_at_boundary:
                            continue
                    
                    # --- NEW: Percentage/ratio check ---
                    # Only applied when brand is NOT at a clear boundary.
                    # If the brand is embedded in the middle of a long domain
                    # and is a tiny fraction of it, it's likely coincidental.
                    # e.g., "sage" (4 chars) in "massagetherapy" (14 chars) = 29% → skip
                    # But "sage" at start of "sageconsulting" → skip ratio (at boundary)
                    if not is_at_boundary and brand_min_domain_ratio > 0 and len(normalized) > 0:
                        ratio = len(brand_normalized) / len(normalized)
                        if ratio < brand_min_domain_ratio:
                            continue
                    
                    # --- NEW: Allowlist check ---
                    # If any allowlisted word appears in the normalized domain and
                    # spans the position where the brand was found, suppress the match.
                    # e.g., "first" is allowlisted, and "irs" is found inside "first"
                    #        within "godfirstdigital" → suppress
                    allowlisted = False
                    for allowed_word in brand_allowlist_words:
                        if allowed_word in normalized:
                            # Check if the allowed word overlaps with the brand match
                            aw_pos = normalized.find(allowed_word)
                            aw_end = aw_pos + len(allowed_word)
                            # Overlap check: brand is within or overlaps the allowed word
                            if aw_pos <= brand_pos and aw_end >= brand_end:
                                allowlisted = True
                                break
                    
                    if allowlisted:
                        continue
                    
                    matched_brand = brand
                    matched_brand_normalized = brand_normalized
                    result["domain_impersonates_brand"] = brand
                    result["patterns_found"].append(f"brand:{brand}")
                    result["risk_score_addition"] += 20
                    break
    
    # === CHECK 5: Brand + Spoofing Keyword Detection (v5.2) ===
    # If a brand was found, check if the remaining text is a spoofing keyword.
    # This catches easyjetconnect.com, amazonverify.net, chaselogin.com, etc.
    # These are MUCH higher risk than a brand name alone because they specifically
    # mimic legitimate brand service names/subdomains.
    if matched_brand_normalized:
        # Extract the non-brand portion of the domain name
        brand_pos = normalized.find(matched_brand_normalized)
        if brand_pos >= 0:
            before_brand = normalized[:brand_pos]
            after_brand = normalized[brand_pos + len(matched_brand_normalized):]
            
            # Check both portions for spoofing keywords
            for keyword in BRAND_SPOOFING_KEYWORDS:
                keyword_lower = keyword.lower()
                # Check after the brand: easyjet[connect], amazon[verify]
                if after_brand and (after_brand == keyword_lower or after_brand.startswith(keyword_lower)):
                    result["brand_spoofing_keyword"] = keyword
                    result["brand_plus_keyword"] = True
                    result["patterns_found"].append(f"brand_keyword:{matched_brand}+{keyword}")
                    result["risk_score_addition"] += 15  # Additional on top of brand impersonation
                    break
                # Check before the brand: [my]paypal, [secure]chase
                if before_brand and (before_brand == keyword_lower or before_brand.endswith(keyword_lower)):
                    result["brand_spoofing_keyword"] = keyword
                    result["brand_plus_keyword"] = True
                    result["patterns_found"].append(f"brand_keyword:{keyword}+{matched_brand}")
                    result["risk_score_addition"] += 15
                    break
    
    return result


# ============================================================================
# TLD VARIANT SPOOFING DETECTION
# ============================================================================
# Detects when a signup domain is a TLD variant of an established business.
# Example: gordondown.uk spoofing gordondown.co.uk
# The .uk/.co.uk pair is the most common UK spoofing vector, but we also
# check .com and other high-value TLD pairs.
# ============================================================================

# TLD variant pairs to check — order matters: (signup_suffix, variant_suffix)
# We generate variants by stripping the signup TLD and appending the variant TLD.
# These are checked bidirectionally via the generation logic below.
UK_TLD_VARIANTS = [
    ('.uk', '.co.uk'),
    ('.co.uk', '.uk'),
    ('.uk', '.org.uk'),
    ('.org.uk', '.uk'),
]

# Always-check TLD variants (appended to base name regardless of signup TLD)
UNIVERSAL_TLD_VARIANTS = ['.com']

# Additional pairs for non-UK domains
EXTRA_TLD_VARIANTS = [
    ('.co', '.com'),
    ('.io', '.com'),
    ('.net', '.com'),
    ('.org', '.com'),
    ('.app', '.com'),
]

# Minimum word count for a page to be considered "substantive"
VARIANT_CONTENT_THRESHOLD = 80
# Minimum word count disparity ratio (variant must have N× more words)
VARIANT_CONTENT_RATIO = 4
# Minimum email auth signals on variant for asymmetry flag
VARIANT_EMAIL_AUTH_MIN = 2  # e.g., SPF + MX, or SPF + DKIM


def _extract_base_and_tld(domain: str) -> Tuple[str, str]:
    """
    Extract the registrable base name and its effective TLD.
    
    Uses dynamic detection: any two-letter SLD indicator (com, co, org, net, 
    ac, gov, edu, etc.) followed by a two-letter ccTLD is treated as a compound
    TLD. This handles .com.pk, .co.id, .org.za, etc. without hardcoding.
    
    Examples:
        gordondown.uk       → ("gordondown", ".uk")
        gordondown.co.uk    → ("gordondown", ".co.uk")
        example.com         → ("example", ".com")
        mysite.org.uk       → ("mysite", ".org.uk")
        taleem.com.pk       → ("taleem", ".com.pk")
        web.gr8asia.in      → ("gr8asia", ".in")
    """
    domain = domain.lower().strip().rstrip('.')
    
    # Known SLD indicators that form compound TLDs when followed by a ccTLD
    # e.g., "com" in .com.pk, "co" in .co.uk, "org" in .org.za
    SLD_INDICATORS = {'com', 'co', 'org', 'net', 'ac', 'gov', 'edu', 'me', 'gen', 'mil'}
    
    parts = domain.split('.')
    
    if len(parts) >= 3:
        # Check if last two labels form a compound TLD
        # e.g., parts = ['taleem', 'com', 'pk'] → sld='com', cctld='pk'
        sld = parts[-2]   # e.g., 'com'
        cctld = parts[-1] # e.g., 'pk'
        
        # Compound TLD: SLD indicator + 2-3 letter ccTLD
        if sld in SLD_INDICATORS and len(cctld) <= 3:
            compound = f'.{sld}.{cctld}'
            base = parts[-3]  # The registrable name
            return base, compound
    
    if len(parts) >= 2:
        # Simple TLD: example.com, gordondown.uk
        base = parts[-2]
        tld = '.' + parts[-1]
        return base, tld
    
    return domain, ""


def _generate_tld_variants(domain: str) -> List[str]:
    """
    Generate TLD variant domains to check for the given signup domain.
    
    For gordondown.uk → ["gordondown.co.uk", "gordondown.com"]
    For gordondown.co.uk → ["gordondown.uk", "gordondown.com"]
    For example.com → ["example.co.uk", "example.net", "example.org"] (if .com)
    """
    base, tld = _extract_base_and_tld(domain)
    if not base or not tld:
        return []
    
    variants = set()
    
    # Check UK-specific TLD pairs
    for signup_tld, variant_tld in UK_TLD_VARIANTS:
        if tld == signup_tld:
            candidate = base + variant_tld
            if candidate != domain.lower():
                variants.add(candidate)
    
    # Check other TLD pairs
    for signup_tld, variant_tld in EXTRA_TLD_VARIANTS:
        if tld == signup_tld:
            candidate = base + variant_tld
            if candidate != domain.lower():
                variants.add(candidate)
    
    # Always check .com if the signup domain isn't .com
    if tld != '.com':
        candidate = base + '.com'
        if candidate != domain.lower():
            variants.add(candidate)
    
    # If the signup IS .com, check .co.uk (common UK business TLD)
    if tld == '.com':
        variants.add(base + '.co.uk')
    
    return list(variants)


def _count_page_words(content: bytes) -> int:
    """Count words in HTML content (strip tags first)."""
    if not content:
        return 0
    try:
        text = content.decode('utf-8', errors='ignore')
    except Exception:
        text = str(content)
    
    # Remove script/style blocks
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove HTML entities
    text = re.sub(r'&[a-zA-Z]+;', ' ', text)
    text = re.sub(r'&#?\w+;', ' ', text)
    # Collapse whitespace and count
    words = text.split()
    # Filter out very short tokens (likely artifacts)
    words = [w for w in words if len(w) >= 2]
    return len(words)


def _check_variant_email_infra(variant_domain: str) -> Dict:
    """Quick email infrastructure check on a variant domain."""
    result = {
        "spf_exists": False,
        "dkim_exists": False,
        "mx_exists": False,
        "dmarc_exists": False,
        "auth_count": 0,
        "mx_selfhosted": False,
        "mx_external": False,       # True if MX points to known provider (not self-hosted)
        "mx_hosts": [],             # Raw MX hostnames for diagnostics
    }
    
    # SPF
    _, spf_exists, _ = get_spf(variant_domain)
    result["spf_exists"] = spf_exists
    
    # MX
    mx_exists, mx_records, _ = get_mx(variant_domain)
    result["mx_exists"] = mx_exists
    
    if mx_exists and mx_records:
        all_mx_hosts = [h.lower() for _, h in mx_records]
        result["mx_hosts"] = all_mx_hosts
        
        domain_lower = variant_domain.lower()
        
        # Check self-hosted: MX points to own domain or subdomain
        is_selfhosted = any(
            h == domain_lower or h.endswith('.' + domain_lower) 
            for h in all_mx_hosts
        )
        result["mx_selfhosted"] = is_selfhosted
        
        # Check external provider (enterprise or standard patterns)
        # These are common hosted email providers — if MX points here, it's external
        EXTERNAL_MX_PATTERNS = [
            # Enterprise
            'google.com', 'googlemail.com', 'outlook.com', 'microsoft.com',
            'protection.outlook.com', 'ppe-hosted.com',
            # Standard  
            'mxroute.com', 'zoho.com', 'fastmail.com', 'protonmail.ch',
            'messagingengine.com', 'migadu.com', 'tutanota.de',
            'emailsrvr.com', 'secureserver.net', 'icloud.com',
            'registrar-servers.com', 'hostinger.com', 'ionos.com',
            'dreamhost.com', 'bluehost.com', 'siteground.net',
            'ovh.net', 'gandi.net', 'namecheap.com',
        ]
        result["mx_external"] = not is_selfhosted and any(
            any(pattern in h for pattern in EXTERNAL_MX_PATTERNS)
            for h in all_mx_hosts
        )
    
    # DMARC
    _, dmarc_exists, _ = get_dmarc(variant_domain)
    result["dmarc_exists"] = dmarc_exists
    
    # DKIM (quick check — just try a few common selectors)
    dkim_exists, _ = check_dkim(variant_domain)
    result["dkim_exists"] = dkim_exists
    
    result["auth_count"] = sum([
        result["spf_exists"],
        result["dkim_exists"],
        result["mx_exists"],
        result["dmarc_exists"],
    ])
    
    return result


def _check_variant_content_indicators(content: bytes) -> Dict:
    """Check for business legitimacy indicators in variant page content."""
    result = {
        "has_navigation": False,
        "has_contact_info": False,
        "has_company_number": False,
        "has_vat_number": False,
        "has_professional_membership": False,
        "has_multiple_pages": False,
        "indicator_count": 0,
    }
    
    if not content:
        return result
    
    text = content.decode('utf-8', errors='ignore').lower()
    
    # Navigation links (suggests multi-page site)
    nav_patterns = [
        r'<nav\b', r'class="nav', r'class="menu', r'id="menu',
        r'<ul[^>]*class="[^"]*nav', r'role="navigation"',
    ]
    result["has_navigation"] = any(re.search(p, text) for p in nav_patterns)
    
    # Multiple internal links (more than just a placeholder)
    internal_links = re.findall(r'<a\s+[^>]*href=["\'](?!/|#|http|mailto|tel)[^"\']+["\']', text)
    relative_links = re.findall(r'<a\s+[^>]*href=["\']/[^"\']+["\']', text)
    result["has_multiple_pages"] = (len(internal_links) + len(relative_links)) >= 3
    
    # Contact information
    contact_patterns = [
        r'\b\d{3,5}\s?\d{3,4}\s?\d{3,4}\b',  # Phone numbers
        r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b',  # Email addresses
        r'\bcontact\s*us\b', r'\bget\s*in\s*touch\b',
    ]
    result["has_contact_info"] = any(re.search(p, text) for p in contact_patterns)
    
    # Company registration number (UK Companies House format, or generic)
    company_patterns = [
        r'company\s*(?:number|no\.?|registration|reg\.?)\s*[:.]?\s*\d{6,8}',
        r'registered\s*(?:in\s+)?(?:england|wales|scotland)\b',
        r'companies\s*house\b',
    ]
    result["has_company_number"] = any(re.search(p, text) for p in company_patterns)
    
    # VAT number
    vat_patterns = [
        r'vat\s*(?:number|no\.?|reg\.?)\s*[:.]?\s*(?:gb)?\s*\d{9}',
        r'vat\s*[:.]?\s*(?:gb)?\s*\d{3}\s*\d{4}\s*\d{2}',
    ]
    result["has_vat_number"] = any(re.search(p, text) for p in vat_patterns)
    
    # Professional memberships (accounting, legal, etc.)
    membership_patterns = [
        r'\bicaew\b', r'\bacca\b', r'\bciot\b', r'\bcima\b',  # Accounting
        r'\bsra\b', r'\blaw\s*society\b',  # Legal
        r'\brics\b', r'\briba\b',  # Property/Architecture
        r'\bfca\b', r'\bcertified\s+accountant', r'\bchartered\b',
    ]
    result["has_professional_membership"] = any(re.search(p, text) for p in membership_patterns)
    
    result["indicator_count"] = sum([
        result["has_navigation"],
        result["has_contact_info"],
        result["has_company_number"],
        result["has_vat_number"],
        result["has_professional_membership"],
        result["has_multiple_pages"],
    ])
    
    return result


def check_tld_variant_spoofing(domain: str, signup_content: bytes = None, 
                                 timeout: float = 8.0) -> Dict:
    """
    Check if the signup domain is a TLD variant of an established business domain.
    
    This catches the gordondown.uk-spoofing-gordondown.co.uk pattern:
    - Generate TLD variants of the signup domain
    - Check if any variant resolves to an established business
    - Compare content and email infrastructure asymmetry
    
    Returns dict with detection results.
    """
    result = {
        "tld_variant_detected": False,
        "variant_domain": "",
        "variant_has_content": False,
        "variant_has_email_infra": False,
        "variant_domain_age_days": -1,
        "variant_content_words": 0,
        "signup_content_words": 0,
        "summary": "",
    }
    
    # Count words on signup domain's page
    signup_words = _count_page_words(signup_content) if signup_content else 0
    result["signup_content_words"] = signup_words
    
    # Check signup domain's own email infrastructure (for disparity comparison)
    signup_email = _check_variant_email_infra(domain)
    
    # Generate TLD variants
    variants = _generate_tld_variants(domain)
    if not variants:
        return result
    
    best_variant = None
    best_score = 0  # Track the "most established" variant
    diagnostics = []  # Track what we found for debug output
    
    for variant_domain in variants:
        # Step 1: DNS resolution — does the variant exist?
        try:
            socket.gethostbyname(variant_domain)
        except Exception:
            diagnostics.append(f"{variant_domain}: no DNS")
            continue  # Variant doesn't resolve — skip
        
        # Step 2: Fetch variant's page content
        variant_content = None
        if REQUESTS_AVAILABLE:
            variant_http = follow_redirects(f"https://{variant_domain}", timeout, fetch_content=True)
            if variant_http["ok"]:
                variant_content = variant_http["content"]
            else:
                # Try HTTP if HTTPS fails
                variant_http = follow_redirects(f"http://{variant_domain}", timeout, fetch_content=True)
                if variant_http["ok"]:
                    variant_content = variant_http["content"]
        
        variant_words = _count_page_words(variant_content)
        
        # Step 3: Check email infrastructure on variant
        variant_email = _check_variant_email_infra(variant_domain)
        
        # Step 4: Check content legitimacy indicators
        variant_indicators = _check_variant_content_indicators(variant_content)
        
        # Step 5: Calculate asymmetry score
        # Higher = more likely the variant is the real business and signup is the spoof
        asymmetry_score = 0
        score_reasons = []
        
        # --- SIGNUP HOLLOWNESS (independent signal) ---
        # A near-empty signup page is suspicious on its own when a variant exists
        if signup_words < 30:
            asymmetry_score += 2
            score_reasons.append(f"signup hollow ({signup_words}w)")
            # Variant has ANY meaningful content (even SPA shell with meta/titles)
            if variant_words >= 30:
                asymmetry_score += 1
                score_reasons.append(f"variant has content ({variant_words}w)")
        
        # --- CONTENT VOLUME ASYMMETRY ---
        if variant_words >= VARIANT_CONTENT_THRESHOLD:
            asymmetry_score += 1
            score_reasons.append(f"variant substantive ({variant_words}w)")
            if signup_words < 50:
                asymmetry_score += 1  # Big disparity
                score_reasons.append("content disparity")
        
        # --- EMAIL INFRASTRUCTURE ON VARIANT ---
        if variant_email["auth_count"] >= VARIANT_EMAIL_AUTH_MIN:
            asymmetry_score += 2
            score_reasons.append(f"variant email auth ({variant_email['auth_count']}/4)")
            if variant_email["auth_count"] >= 3:
                asymmetry_score += 1
                score_reasons.append("variant strong email")
        
        # --- EMAIL AUTH DISPARITY (variant vs signup) ---
        # If variant has significantly better email auth than signup, strong signal
        email_gap = variant_email["auth_count"] - signup_email["auth_count"]
        if email_gap >= 2:
            asymmetry_score += 2
            score_reasons.append(f"email disparity (variant {variant_email['auth_count']} vs signup {signup_email['auth_count']})")
        elif email_gap >= 1:
            asymmetry_score += 1
            score_reasons.append(f"email gap +{email_gap}")
        
        # --- MX TYPE DISPARITY ---
        # Signup has self-hosted MX (mail.domain.uk) while variant has external provider
        # This is a strong spoof signal: real businesses use hosted email, spoofs point MX at themselves
        if signup_email["mx_selfhosted"] and variant_email["mx_external"]:
            asymmetry_score += 2
            score_reasons.append(f"MX disparity (signup selfhosted vs variant external)")
        elif signup_email["mx_selfhosted"] and not variant_email["mx_selfhosted"]:
            # Variant at least isn't selfhosted, even if we can't confirm provider
            asymmetry_score += 1
            score_reasons.append(f"signup MX selfhosted")
        
        # --- BUSINESS LEGITIMACY INDICATORS ---
        if variant_indicators["indicator_count"] >= 2:
            asymmetry_score += 2
            score_reasons.append(f"biz indicators ({variant_indicators['indicator_count']})")
        if variant_indicators["indicator_count"] >= 4:
            asymmetry_score += 1
        
        # Company registration is a very strong signal
        if variant_indicators["has_company_number"]:
            asymmetry_score += 2
            score_reasons.append("company reg found")
        
        diag = f"{variant_domain}: score={asymmetry_score} [{', '.join(score_reasons)}] words={variant_words} email={variant_email['auth_count']}/4 mx_ext={variant_email['mx_external']}"
        diagnostics.append(diag)
        
        # Track best variant
        if asymmetry_score > best_score:
            best_score = asymmetry_score
            best_variant = {
                "domain": variant_domain,
                "words": variant_words,
                "email": variant_email,
                "indicators": variant_indicators,
                "score": asymmetry_score,
                "content": variant_content,
                "score_reasons": score_reasons,
            }
    
    # Decision: flag if asymmetry score is high enough
    # Threshold: score >= 5 means clear asymmetry (established variant vs hollow signup)
    DETECTION_THRESHOLD = 5
    
    if best_variant and best_variant["score"] >= DETECTION_THRESHOLD:
        v = best_variant
        result["tld_variant_detected"] = True
        result["variant_domain"] = v["domain"]
        result["variant_has_content"] = v["words"] >= VARIANT_CONTENT_THRESHOLD
        result["variant_has_email_infra"] = v["email"]["auth_count"] >= VARIANT_EMAIL_AUTH_MIN
        result["variant_content_words"] = v["words"]
        
        # Build human-readable summary
        summary_parts = []
        summary_parts.append(f"TLD VARIANT: {v['domain']}")
        
        # Content comparison
        summary_parts.append(f"variant has {v['words']} words vs signup has {signup_words} words")
        
        # Email infra
        email_signals = []
        if v["email"]["spf_exists"]:
            email_signals.append("SPF")
        if v["email"]["dkim_exists"]:
            email_signals.append("DKIM")
        if v["email"]["mx_exists"]:
            email_signals.append("MX")
        if v["email"]["dmarc_exists"]:
            email_signals.append("DMARC")
        if email_signals:
            summary_parts.append(f"variant email auth: {'+'.join(email_signals)}")
        
        # Signup email weakness
        signup_signals = []
        if signup_email["spf_exists"]:
            signup_signals.append("SPF")
        if signup_email["dkim_exists"]:
            signup_signals.append("DKIM")
        if signup_email["mx_exists"]:
            if signup_email["mx_selfhosted"]:
                signup_signals.append("MX(selfhosted)")
            else:
                signup_signals.append("MX")
        if signup_email["dmarc_exists"]:
            signup_signals.append("DMARC")
        summary_parts.append(f"signup email auth: {'+'.join(signup_signals) if signup_signals else 'none'}")
        
        # Business indicators
        biz_signals = []
        if v["indicators"]["has_company_number"]:
            biz_signals.append("company reg")
        if v["indicators"]["has_vat_number"]:
            biz_signals.append("VAT")
        if v["indicators"]["has_professional_membership"]:
            biz_signals.append("professional body")
        if v["indicators"]["has_navigation"]:
            biz_signals.append("full site")
        if v["indicators"]["has_contact_info"]:
            biz_signals.append("contact info")
        if biz_signals:
            summary_parts.append(f"variant signals: {', '.join(biz_signals)}")
        
        summary_parts.append(f"asymmetry: {v['score']}")
        result["summary"] = " → ".join(summary_parts)
    
    else:
        # Always provide diagnostic output so we can see what happened
        mx_type = "selfhosted" if signup_email["mx_selfhosted"] else ("external" if signup_email["mx_external"] else "unknown")
        diag_summary = f"TLD VARIANT CHECK: signup={signup_words}w, signup_email={signup_email['auth_count']}/4, signup_mx={mx_type}"
        if diagnostics:
            diag_summary += " | " + " | ".join(diagnostics)
        else:
            diag_summary += " | no variants resolved"
        if best_variant:
            diag_summary += f" | best={best_variant['domain']} score={best_variant['score']} (threshold={DETECTION_THRESHOLD})"
        result["summary"] = diag_summary
    
    return result


# ============================================================================
# WEB FUNCTIONS
# ============================================================================

def check_tls(domain: str, timeout: float) -> Dict:
    """
    Probe TLS on port 443 and classify the failure mode.
    
    v4.4: Now explicitly catches ssl.SSLError for handshake failures
    (cipher mismatch, protocol version, SSLV3_ALERT_HANDSHAKE_FAILURE, etc.)
    instead of letting them fall through to a generic except.
    
    Returns:
        ok                – handshake + cert verification succeeded
        error             – human-readable error (empty on success)
        handshake_failed  – SSL negotiation itself failed
        connection_failed – TCP layer failed (refused, timeout, unreachable)
        self_signed       – certificate is self-signed
        expired           – certificate is expired
        wrong_host        – certificate CN/SAN doesn't match domain
    """
    result = {
        "ok": False,
        "error": "",
        "handshake_failed": False,
        "connection_failed": False,
        "self_signed": False,
        "expired": False,
        "wrong_host": False,
    }
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                result["ok"] = True

    # Certificate exists but fails validation
    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        result["error"] = str(e)[:200]
        result["self_signed"] = "self signed" in err or "self-signed" in err
        result["expired"] = "expired" in err
        result["wrong_host"] = "hostname" in err or "match" in err

    # v4.4 FIX: Handshake-level failures — previously fell through to generic except
    # Fires for: SSLV3_ALERT_HANDSHAKE_FAILURE, TLSV1_ALERT_PROTOCOL_VERSION,
    # EOF occurred in violation of protocol, cipher mismatch, connection reset during handshake
    except ssl.SSLError as e:
        result["error"] = str(e)[:200]
        result["handshake_failed"] = True

    # DNS resolution failure or TCP timeout
    except (socket.timeout, socket.gaierror) as e:
        result["error"] = str(e)[:200]
        result["connection_failed"] = True

    # Port 443 is closed / nothing listening
    except ConnectionRefusedError as e:
        result["error"] = f"Connection refused on port 443: {e}"[:200]
        result["connection_failed"] = True

    # Network unreachable, host unreachable, etc.
    except OSError as e:
        result["error"] = str(e)[:200]
        result["connection_failed"] = True

    return result


def follow_redirects(url: str, timeout: float, fetch_content: bool = False) -> Dict:
    """
    Follow HTTP redirect chain and optionally fetch final content.
    
    v4.4: Replaced bare `except:` with typed exception handling so SSL errors,
    connection errors, and timeouts are captured in separate result fields
    instead of being silently swallowed.
    """
    if not REQUESTS_AVAILABLE:
        return {"ok": False, "initial_status": 0, "hops": 0, "chain": [], "domains": [], 
                "cross_domain": False, "uses_temp": False, "final_url": url, 
                "all_statuses": set(), "content": b"", "content_length": -1,
                "ssl_error": "", "connection_error": "", "timeout_error": "", "error": ""}
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
    
    result = {
        "ok": False, "initial_status": 0, "hops": 0,
        "chain": [], "domains": [], "cross_domain": False,
        "uses_temp": False, "final_url": url, "all_statuses": set(),
        "content": b"", "content_length": -1,
        # v4.4: typed error fields (was bare except that discarded all info)
        "ssl_error": "",
        "connection_error": "",
        "timeout_error": "",
        "error": "",
    }
    
    start_host = urlparse(url).netloc.lower()
    current = url
    seen = set()
    
    for i in range(MAX_REDIRECTS + 1):
        if current in seen:
            break
        seen.add(current)
        host = urlparse(current).netloc.lower()
        if host and host not in result["domains"]:
            result["domains"].append(host)
        
        try:
            # Use HEAD for redirect chasing (fast), GET only when we need content
            resp = session.head(current, allow_redirects=False, timeout=timeout, verify=True)
            status = resp.status_code
            
            if status in (405, 501):
                resp = session.get(current, allow_redirects=False, timeout=timeout, verify=True)
                status = resp.status_code
            
            if i == 0:
                result["initial_status"] = status
            result["all_statuses"].add(status)
            
            if status in ALL_REDIRECT_CODES and "Location" in resp.headers:
                result["chain"].append(status)
                if status in TEMP_REDIRECT_CODES:
                    result["uses_temp"] = True
                next_url = urljoin(current, resp.headers["Location"])
                next_host = urlparse(next_url).netloc.lower()
                if next_host and next_host != start_host:
                    result["cross_domain"] = True
                current = next_url
                result["hops"] += 1
                continue
            
            result["ok"] = True
            result["final_url"] = current
            result["chain"].append(status)
            
            # Non-redirect final response — fetch body with GET if caller wants content
            if fetch_content:
                try:
                    get_resp = session.get(current, allow_redirects=False, timeout=timeout, verify=True)
                    result["content"] = get_resp.content[:50000]
                    result["content_length"] = len(result["content"])
                except Exception as e:
                    result["error"] = f"content_read_failed: {str(e)[:150]}"
            return result

        # v4.4 FIX: typed exception handling (was bare `except:` that silently returned)
        except requests.exceptions.SSLError as e:
            result["ssl_error"] = str(e)[:200]
            result["ok"] = False
            return result

        except requests.exceptions.ConnectionError as e:
            result["connection_error"] = str(e)[:200]
            result["ok"] = False
            return result

        except requests.exceptions.Timeout as e:
            result["timeout_error"] = str(e)[:200]
            result["ok"] = False
            return result

        except Exception as e:
            result["error"] = str(e)[:200]
            result["ok"] = False
            return result
    
    result["ok"] = True
    return result


def analyze_content(content: bytes, final_url: str, domain: str) -> Dict:
    result = {
        "minimal_shell": False, "js_redirect": False, "meta_refresh": False,
        "external_js": False, "obfuscation": False, "credential_form": False,
        "sensitive_fields": False, "brands": [], "form_external": False,
        "malware": [], "suspicious_iframe": False, "parking": False, "phishing_paths": [],
    }
    
    if not content:
        return result
    
    content_lower = content.lower()
    content_len = len(content.strip())
    
    has_script = b'<script' in content_lower
    body = re.sub(rb'<script[^>]*>.*?</script>', b'', content_lower, flags=re.DOTALL)
    if content_len < 1000 and has_script and len(body.strip()) < 300:
        result["minimal_shell"] = True
    
    for p in JS_REDIRECT_PATTERNS:
        if p in content_lower:
            result["js_redirect"] = True
            break
    
    if re.search(rb'<meta[^>]+http-equiv=["\']?refresh', content_lower):
        result["meta_refresh"] = True
    
    if content_len < 2000 and re.search(rb'<script[^>]+src=', content_lower):
        result["external_js"] = True
    
    obf = [rb'fromCharCode', rb'eval\s*\(', rb'atob\s*\(', rb'\\x[0-9a-f]{2}']
    if sum(1 for p in obf if re.search(p, content_lower)) >= 2:
        result["obfuscation"] = True
    
    for p in CREDENTIAL_PATTERNS:
        if p in content_lower:
            result["credential_form"] = True
            break
    
    for p in SENSITIVE_PATTERNS:
        if p in content_lower:
            result["sensitive_fields"] = True
            break
    
    final_domain = urlparse(final_url).netloc.lower()
    
    # Check for brand keywords in page content
    for brand in BRAND_KEYWORDS:
        brand_str = brand.decode('utf-8', errors='ignore').replace(' ', '')
        if brand in content_lower and brand_str not in final_domain and brand_str not in domain:
            result["brands"].append(brand.decode('utf-8', errors='ignore'))
    
    # Check short brand keywords with word boundary matching (to avoid "first" matching "irs")
    content_str = content_lower.decode('utf-8', errors='ignore')
    for brand in BRAND_KEYWORDS_SHORT:
        brand_str = brand.decode('utf-8', errors='ignore')
        if brand_str not in final_domain and brand_str not in domain:
            # Use word boundary regex to avoid false positives
            pattern = r'\b' + re.escape(brand_str) + r'\b'
            if re.search(pattern, content_str, re.IGNORECASE):
                result["brands"].append(brand_str)
    
    result["brands"] = list(set(result["brands"]))[:5]  # Dedupe and limit
    
    forms = re.findall(rb'<form[^>]+action=["\']([^"\']+)["\']', content_lower)
    for action in forms:
        try:
            action_url = action.decode('utf-8', errors='ignore')
            if action_url.startswith(('http://', 'https://')):
                action_host = urlparse(action_url).netloc.lower()
                if action_host and action_host != final_domain:
                    result["form_external"] = True
                    break
        except:
            pass
    
    links = re.findall(rb'(?:href|src)=["\']([^"\']+)["\']', content_lower)
    for link in links:
        try:
            link_str = link.decode('utf-8', errors='ignore').lower()
            for ext in MALWARE_EXTENSIONS:
                if link_str.endswith(ext):
                    result["malware"].append(ext)
                    break
        except:
            pass
    result["malware"] = list(set(result["malware"]))[:5]
    
    if re.search(rb'<iframe[^>]*(?:display:\s*none|width=["\']?[01])', content_lower):
        result["suspicious_iframe"] = True
    
    for p in [b'domain for sale', b'buy this domain', b'parked']:
        if p in content_lower:
            result["parking"] = True
            break
    
    path = urlparse(final_url).path.lower()
    for p in PHISHING_PATHS:
        if p in path:
            result["phishing_paths"].append(p)
    
    return result


def analyze_ecommerce_indicators(content: bytes, domain: str) -> Dict:
    """
    Detect e-commerce site indicators and business legitimacy signals.
    
    Helps identify:
    1. Whether site is an e-commerce store
    2. Whether it has proper business identity disclosure
    3. Cross-domain brand links (fragmentation indicator)
    """
    result = {
        "is_ecommerce": False,
        "ecommerce_signals": [],
        "has_business_identity": False,
        "business_identity_signals": [],
        "missing_identity_signals": [],
        "cross_domain_brand_links": [],
    }
    
    if not content:
        return result
    
    content_str = content.decode('utf-8', errors='ignore').lower()
    
    # === E-COMMERCE DETECTION ===
    ecom_count = 0
    for indicator in ECOMMERCE_INDICATORS:
        if indicator in content_str:
            result["ecommerce_signals"].append(indicator)
            ecom_count += 1
    
    # Consider it e-commerce if 3+ indicators present
    if ecom_count >= 3:
        result["is_ecommerce"] = True
    
    # === BUSINESS IDENTITY DETECTION ===
    identity_signals = []
    
    # Check for legal entity patterns
    if re.search(r'\b(inc|llc|ltd|corp|corporation|gmbh|sarl|pty|co\.)\b', content_str, re.IGNORECASE):
        identity_signals.append("legal_entity")
    
    # Check for registration numbers
    if re.search(r'(registration|reg\.?\s*no|business\s*number|company\s*number|ein|vat|abn|tax\s*id)\s*[:.\s#]*[\w\d-]{5,}', content_str, re.IGNORECASE):
        identity_signals.append("registration_number")
    
    # Check for physical address
    if re.search(r'\d+\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct|place|pl)', content_str, re.IGNORECASE):
        identity_signals.append("physical_address")
    
    # Check for "About Us" with substantial content
    if re.search(r'about\s*(us|our\s*company|the\s*company|who\s*we\s*are)', content_str, re.IGNORECASE):
        identity_signals.append("about_page")
    
    # Check for contact information
    if re.search(r'contact\s*(us|info|information)', content_str, re.IGNORECASE):
        identity_signals.append("contact_info")
    
    # Check for terms/privacy
    if re.search(r'(terms\s*(of|and)\s*(service|use)|privacy\s*policy|refund\s*policy|return\s*policy)', content_str, re.IGNORECASE):
        identity_signals.append("legal_policies")
    
    result["business_identity_signals"] = identity_signals
    result["has_business_identity"] = len(identity_signals) >= 3
    
    # What's missing (important for e-commerce sites)
    if result["is_ecommerce"]:
        expected = ["legal_entity", "physical_address", "legal_policies"]
        missing = [s for s in expected if s not in identity_signals]
        result["missing_identity_signals"] = missing
    
    # === CROSS-DOMAIN BRAND LINK DETECTION ===
    # Extract domain name without TLD for comparison
    domain_parts = domain.lower().split('.')
    if len(domain_parts) >= 2:
        # Get the "brand" part (e.g., "gabyandbeauty" from "gabyandbeauty.shop")
        brand_name = domain_parts[0] if len(domain_parts) == 2 else '.'.join(domain_parts[:-1])
        current_tld = '.' + domain_parts[-1]
        
        # Find all links in content
        links = re.findall(r'href=["\']([^"\']+)["\']', content_str, re.IGNORECASE)
        
        for link in links:
            try:
                # Parse the link
                if link.startswith('http'):
                    parsed = urlparse(link)
                    link_domain = parsed.netloc.lower()
                    
                    # Check if link contains same brand but different TLD
                    if link_domain and link_domain != domain:
                        link_parts = link_domain.split('.')
                        if len(link_parts) >= 2:
                            link_brand = link_parts[0] if len(link_parts) == 2 else '.'.join(link_parts[:-1])
                            link_tld = '.' + link_parts[-1]
                            
                            # Same brand, different TLD = suspicious
                            if link_brand == brand_name and link_tld != current_tld:
                                result["cross_domain_brand_links"].append(link_domain)
                            
                            # Similar brand (80%+ match) = also suspicious
                            elif difflib.SequenceMatcher(None, brand_name, link_brand).ratio() > 0.8:
                                result["cross_domain_brand_links"].append(link_domain)
            except:
                pass
        
        result["cross_domain_brand_links"] = list(set(result["cross_domain_brand_links"]))[:5]
    
    return result


def check_hijacked_domain_indicators(content: bytes, final_url: str, redirect_chain: List[str] = None) -> Dict:
    """
    Detect indicators of hijacked/compromised domains being used as phishing stepping stones.
    
    Based on research: https://keepaware.com/blog/over-100-domains-hijacked
    
    Key indicators:
    1. Suspicious URL path patterns (e.g., /tunnel/, /bid/, /invite/)
    2. Document sharing lure content
    3. Phishing kit JavaScript behaviors (atob, hash extraction, etc.)
    4. Redirects to known phishing infrastructure (workers.dev, etc.)
    5. Email tracking in URL hash
    """
    result = {
        "has_hijack_path": False,
        "hijack_path": "",
        "has_doc_lure": False,
        "doc_lure": "",
        "has_phishing_js": False,
        "phishing_js_found": [],
        "redirects_to_phishing_infra": False,
        "phishing_infra": "",
        "has_email_in_url": False,
        "email_tracking": "",
        "risk_score_addition": 0,
    }
    
    if not content and not final_url:
        return result
    
    # === CHECK 1: Suspicious URL path patterns ===
    # Hijacked sites often have phishing pages in paths like /tunnel/, /bid/, /secure/
    if final_url:
        parsed = urlparse(final_url)
        path_lower = parsed.path.lower()
        
        for keyword in HIJACK_PATH_KEYWORDS:
            if f'/{keyword}/' in path_lower or f'/{keyword}' == path_lower or path_lower.startswith(f'/{keyword}'):
                result["has_hijack_path"] = True
                result["hijack_path"] = keyword
                result["risk_score_addition"] += 12
                break
        
        # Check for suspicious filename patterns
        if not result["has_hijack_path"]:
            for pattern in HIJACK_FILE_PATTERNS:
                if pattern in path_lower:
                    result["has_hijack_path"] = True
                    result["hijack_path"] = pattern
                    result["risk_score_addition"] += 8
                    break
        
        # === CHECK 5: Email tracking in URL ===
        # Phishers embed victim email in URL hash: example.com/page#john@company.com
        full_url = final_url
        if '#' in full_url:
            hash_part = full_url.split('#', 1)[1]
            # Check for plain email
            if '@' in hash_part and '.' in hash_part.split('@')[-1]:
                result["has_email_in_url"] = True
                result["email_tracking"] = "plain_email_in_hash"
                result["risk_score_addition"] += 15
            # Check for base64 encoded email (common pattern)
            elif len(hash_part) > 10 and hash_part.replace('=', '').replace('+', '').replace('/', '').isalnum():
                try:
                    import base64
                    decoded = base64.b64decode(hash_part).decode('utf-8', errors='ignore')
                    if '@' in decoded and '.' in decoded:
                        result["has_email_in_url"] = True
                        result["email_tracking"] = "base64_email_in_hash"
                        result["risk_score_addition"] += 18
                except:
                    pass
    
    # === CHECK 4: Redirects to known phishing infrastructure ===
    urls_to_check = [final_url] if final_url else []
    if redirect_chain:
        urls_to_check.extend(redirect_chain)
    
    for url in urls_to_check:
        if url:
            url_lower = url.lower()
            for infra in PHISHING_INFRASTRUCTURE:
                if infra in url_lower:
                    result["redirects_to_phishing_infra"] = True
                    result["phishing_infra"] = infra
                    result["risk_score_addition"] += 20
                    break
        if result["redirects_to_phishing_infra"]:
            break
    
    if not content:
        return result
    
    content_lower = content.lower()
    
    # === CHECK 2: Document sharing lure content ===
    for lure in DOC_SHARING_LURES:
        if lure in content_lower:
            result["has_doc_lure"] = True
            result["doc_lure"] = lure.decode('utf-8', errors='ignore')
            result["risk_score_addition"] += 12
            break
    
    # === CHECK 3: Phishing kit JavaScript behaviors ===
    js_patterns_found = []
    for pattern in PHISHING_JS_PATTERNS:
        if pattern in content_lower:
            js_patterns_found.append(pattern.decode('utf-8', errors='ignore'))
    
    if len(js_patterns_found) >= 2:  # Need 2+ patterns to flag
        result["has_phishing_js"] = True
        result["phishing_js_found"] = js_patterns_found[:5]
        result["risk_score_addition"] += 15
    
    return result


def check_corporate_trust_signals(domain: str, timeout: float = 3.0) -> Dict:
    """
    Check for corporate legitimacy signals by probing common trust pages.
    A legitimate business typically has: /about, /contact, /privacy, /terms, etc.
    
    This is a lightweight check - we just see if these pages return 200 OK.
    """
    result = {
        "pages_checked": [],
        "pages_found": [],
        "missing_trust_signals": False,
        "trust_score": 0,  # Higher = more trustworthy
    }
    
    if not REQUESTS_AVAILABLE:
        return result
    
    # Common corporate trust pages
    TRUST_PAGES = [
        '/about', '/about-us', '/company', '/team',      # Company info
        '/contact', '/contact-us', '/support',            # Contact info
        '/privacy', '/privacy-policy',                    # Legal
        '/terms', '/terms-of-service', '/tos',           # Legal
        '/careers', '/jobs',                              # Established company signal
    ]
    
    base_url = f"https://{domain}"
    
    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        for page in TRUST_PAGES[:8]:  # Check up to 8 pages to limit requests
            result["pages_checked"].append(page)
            try:
                r = session.head(base_url + page, timeout=timeout, allow_redirects=True)
                # Accept 200, 301/302 (redirect to actual page), but not 404/403/401
                if r.status_code in [200, 301, 302]:
                    # For redirects, check if it redirects to a real page (not homepage)
                    if r.status_code in [301, 302]:
                        redirect_to = r.headers.get('Location', '')
                        # If redirect goes back to homepage, don't count it
                        if redirect_to.rstrip('/') == base_url or redirect_to == '/':
                            continue
                    result["pages_found"].append(page)
                    result["trust_score"] += 1
            except:
                continue
        
        session.close()
    except:
        pass
    
    # Missing trust signals if we found 0-1 trust pages out of what we checked
    if len(result["pages_found"]) <= 1 and len(result["pages_checked"]) >= 4:
        result["missing_trust_signals"] = True
    
    return result


def rdap_lookup(domain: str, timeout: float) -> Tuple[str, int]:
    if not REQUESTS_AVAILABLE:
        return "", -1
    try:
        parts = domain.split('.')
        base = '.'.join(parts[-3:]) if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net'] else '.'.join(parts[-2:])
        r = requests.get(f"https://rdap.org/domain/{base}", timeout=timeout)
        if r.status_code != 200:
            return "", -1
        for ev in r.json().get("events", []):
            if ev.get("eventAction", "").lower() == "registration":
                created = ev.get("eventDate")
                if created:
                    dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    return dt.isoformat(), (datetime.now(timezone.utc) - dt).days
        return "", -1
    except:
        return "", -1


def whois_lookup(domain: str) -> Tuple[str, int]:
    """Fallback domain age lookup via python-whois when RDAP fails."""
    if not WHOIS_AVAILABLE:
        return "", -1
    try:
        parts = domain.split('.')
        base = '.'.join(parts[-3:]) if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net'] else '.'.join(parts[-2:])
        w = python_whois.whois(base)
        created = w.creation_date
        if created is None:
            return "", -1
        # Some registrars return a list of dates
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            return created.isoformat(), age_days
        return "", -1
    except Exception:
        return "", -1


def whois_enrich(domain: str) -> dict:
    """
    Extract registrar, statuses, and updated date from WHOIS.
    Used for transfer lock detection and domain takeover signals.
    """
    result = {
        "registrar": "",
        "statuses": [],
        "updated_date": "",
        "updated_days_ago": -1,
        "transfer_locked": True,  # Default safe — only flag if we confirm lock is missing
    }
    if not WHOIS_AVAILABLE:
        return result
    try:
        parts = domain.split('.')
        base = '.'.join(parts[-3:]) if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net'] else '.'.join(parts[-2:])
        w = python_whois.whois(base)
        
        # Registrar
        result["registrar"] = (w.registrar or "")[:200]
        
        # Statuses
        raw_status = w.status
        if raw_status:
            if isinstance(raw_status, str):
                raw_status = [raw_status]
            # Normalize: "clientTransferProhibited https://..." → "clientTransferProhibited"
            statuses = []
            for s in raw_status:
                clean = s.split()[0].strip() if s else ""
                if clean:
                    statuses.append(clean)
            result["statuses"] = statuses
            
            # Transfer lock check
            lock_statuses = {'clienttransferprohibited', 'servertransferprohibited'}
            has_lock = any(s.lower() in lock_statuses for s in statuses)
            result["transfer_locked"] = has_lock
        
        # Updated date
        updated = w.updated_date
        if updated:
            if isinstance(updated, list):
                updated = updated[0]
            if isinstance(updated, datetime):
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                result["updated_date"] = updated.isoformat()
                result["updated_days_ago"] = (datetime.now(timezone.utc) - updated).days
    except Exception:
        pass
    return result


def check_cert_transparency(domain: str, timeout: float = 8.0) -> dict:
    """
    Query crt.sh (Certificate Transparency logs) for domain certificates.
    Reveals certificate issuance history — useful for detecting:
    - Brand-new domains (first cert = recent)
    - Domain takeovers (new cert on old domain)
    - Let's Encrypt churn (mass phishing infra)
    """
    result = {
        "ct_count": -1,
        "recent_issuance": False,
        "issuers": [],
        "first_seen": "",
        "last_seen": "",
    }
    if not REQUESTS_AVAILABLE:
        return result
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout,
            headers={"User-Agent": "DomainApproval/7.1"}
        )
        if r.status_code != 200:
            return result
        
        entries = r.json()
        if not isinstance(entries, list):
            return result
        
        result["ct_count"] = len(entries)
        
        if not entries:
            return result
        
        # Parse dates and issuers
        issuers = set()
        dates = []
        now = datetime.now(timezone.utc)
        
        for entry in entries[:200]:  # Cap processing at 200 certs
            issuer = entry.get("issuer_name", "")
            if issuer:
                # Extract CN or O from issuer DN
                for part in issuer.split(","):
                    part = part.strip()
                    if part.startswith("CN=") or part.startswith("O="):
                        issuers.add(part.split("=", 1)[1].strip())
                        break
            
            not_before = entry.get("not_before", "")
            if not_before:
                try:
                    dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                    dates.append(dt)
                except (ValueError, TypeError):
                    pass
        
        if dates:
            dates.sort()
            result["first_seen"] = dates[0].isoformat()
            result["last_seen"] = dates[-1].isoformat()
            
            # Check if most recent cert was issued within 7 days
            days_since_last = (now - dates[-1]).days
            if days_since_last <= 7:
                result["recent_issuance"] = True
        
        result["issuers"] = sorted(issuers)[:10]  # Cap at 10 unique issuers
        
    except Exception:
        pass
    return result


# ============================================================================
# SCORING & SUMMARY
# ============================================================================

def generate_summary(res: DomainApprovalResult, signals: Set[str], rdap_enabled: bool, weights: dict = None) -> str:
    """Generate comprehensive summary showing ALL triggered signals and their email impacts."""
    
    if weights is None:
        weights = {}
    
    all_issues = []  # Format: "ISSUE → IMPACT"
    positives = []
    
    # === HIGH-RISK PHISHING INFRASTRUCTURE (composite indicator) ===
    if res.high_risk_phish_infra:
        all_issues.append(f"🚨 HIGH-RISK PHISHING INFRA → {res.high_risk_phish_infra_reason}")
    
    # === CRITICAL ISSUES ===
    if res.domain_blacklist_count > 0:
        bl_names = res.domain_blacklists_hit.replace(";", ", ")
        all_issues.append(f"BLACKLISTED DOMAIN on {bl_names} ({res.domain_blacklist_count} lists) → Emails BLOCKED by Gmail/Outlook/Yahoo")
    
    if res.ip_blacklist_count > 0:
        ip_bl_names = res.ip_blacklists_hit.replace(";", ", ")
        all_issues.append(f"BLACKLISTED IP on {ip_bl_names} ({res.ip_blacklist_count} lists) → Emails BLOCKED by major providers")
    
    # v6.2: Warn when blacklist checks were inconclusive (timeout/rate limit)
    total_inconclusive = res.domain_blacklist_inconclusive + res.ip_blacklist_inconclusive
    if total_inconclusive > 0:
        parts = []
        if res.domain_blacklist_inconclusive > 0:
            parts.append(f"{res.domain_blacklist_inconclusive} domain")
        if res.ip_blacklist_inconclusive > 0:
            parts.append(f"{res.ip_blacklist_inconclusive} IP")
        all_issues.append(f"⚠️ BLACKLIST CHECK INCONCLUSIVE ({', '.join(parts)} list(s) timed out) → May be rate-limited; result is NOT confirmed clean")
    
    if res.spf_mechanism == "+all":
        all_issues.append("SPF +all → Domain SPOOFABLE; anyone can forge emails as this sender")
    
    if rdap_enabled and res.domain_age_days >= 0 and res.domain_age_days <= 1:
        src = f" ({res.domain_age_source.upper()})" if res.domain_age_source else ""
        all_issues.append(f"⚠ DOMAIN CREATED TODAY/YESTERDAY{src} → Registered {res.domain_age_days}d ago; near-certain spam/phishing infrastructure")
    elif rdap_enabled and res.domain_age_days >= 0 and res.domain_age_days < 7:
        all_issues.append(f"DOMAIN ONLY {res.domain_age_days} DAYS OLD → New domains hit spam folder 90%+ of the time")
    elif rdap_enabled and res.domain_age_days >= 7 and res.domain_age_days < 30:
        all_issues.append(f"DOMAIN {res.domain_age_days} DAYS OLD → Young domains face increased spam filtering")
    elif rdap_enabled and res.domain_age_days >= 30 and res.domain_age_days < 90:
        all_issues.append(f"DOMAIN {res.domain_age_days} DAYS OLD → Relatively new; building reputation")
    
    if not res.spf_exists and not res.dmarc_exists and not res.dkim_exists:
        all_issues.append("ZERO EMAIL AUTH → Gmail/Yahoo REQUIRE authentication; emails will fail")
    
    if res.is_disposable_email:
        all_issues.append("DISPOSABLE EMAIL DOMAIN → Cannot build sender reputation; inherently untrusted")
    
    if res.typosquat_target:
        all_issues.append(f"TYPOSQUAT of '{res.typosquat_target}' → Triggers phishing/fraud filters automatically")
    
    # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
    if res.domain_impersonates_brand:
        if res.brand_plus_keyword_domain:
            all_issues.append(
                f"BRAND + SPOOFING KEYWORD '{res.domain_impersonates_brand.upper()}' + '{res.brand_spoofing_keyword}' "
                f"→ Domain mimics legitimate brand service/portal (e.g., {res.domain_impersonates_brand}connect.com = phishing)")
        else:
            all_issues.append(f"DOMAIN IMPERSONATES '{res.domain_impersonates_brand.upper()}' → Brand name in domain; classic tech support scam pattern")
    
    # === TLD VARIANT SPOOFING ===
    if res.tld_variant_detected:
        all_issues.append(f"TLD VARIANT SPOOF ({res.tld_variant_domain}) → Established business exists at variant TLD")
    # Diagnostic detail (TLD VARIANT CHECK / CHECK ERROR) is stored in res.tld_variant_summary
    # but NOT shown in issues — it was confusing users into thinking spoofing was detected
    
    if res.has_suspicious_prefix:
        all_issues.append(f"SUSPICIOUS PREFIX '{res.suspicious_prefix_found}' → Common phishing/scam domain pattern")
    
    if res.has_suspicious_suffix:
        all_issues.append(f"SUSPICIOUS SUFFIX '{res.suspicious_suffix_found}' → Tech support scam domain pattern (e.g., 'brandaccount.com')")
    
    if res.is_tech_support_tld:
        all_issues.append("TECH SUPPORT SCAM TLD (.support/.tech/.help) → Heavily abused for scams")
    
    # E-commerce / Retail scam indicators
    if res.is_retail_scam_tld:
        tld = '.' + res.domain.split('.')[-1] if '.' in res.domain else ''
        all_issues.append(f"RETAIL SCAM TLD ({tld}) → .shop/.store TLDs heavily abused for fake stores")
    
    if res.has_cross_domain_brand_link:
        all_issues.append(f"CROSS-DOMAIN BRAND LINKS ({res.cross_domain_brand_links}) → Links to same brand on different TLD; common in clone stores")
    
    if res.is_ecommerce_site and res.missing_business_identity:
        all_issues.append("E-COMMERCE WITHOUT BUSINESS IDENTITY → No legal name/address/registration; high scam risk")
    
    if res.brands_detected:
        all_issues.append(f"BRAND IMPERSONATION ({res.brands_detected}) → Triggers phishing filters")
    
    if res.malware_links_found:
        all_issues.append("MALWARE LINKS DETECTED → Domain will be blacklisted across providers")
    
    if res.has_credential_form and res.brands_detected:
        all_issues.append("CREDENTIAL FORM + BRAND IMPERSONATION → Classic phishing; will be blocked")
    
    # === VIRUSTOTAL REPUTATION ===
    if res.vt_available:
        if res.vt_malicious_count >= 5:
            vendors = res.vt_malicious_vendors.replace(";", ", ")[:100]
            all_issues.append(f"🛡️ VT MALICIOUS ({res.vt_malicious_count}/{res.vt_total_vendors} vendors: {vendors}) → Domain flagged as malicious by security vendors")
        elif res.vt_malicious_count >= 1:
            all_issues.append(f"🛡️ VT FLAGGED ({res.vt_malicious_count} malicious + {res.vt_suspicious_count} suspicious) → Some security vendors flag this domain")
        elif res.vt_suspicious_count >= 1:
            all_issues.append(f"VT SUSPICIOUS ({res.vt_suspicious_count} vendor(s)) → Domain under suspicion by some vendors")
        if res.vt_threat_names:
            names = res.vt_threat_names.replace(";", ", ")
            all_issues.append(f"VT THREAT NAMES: {names}")
        if res.vt_malicious_count == 0 and res.vt_suspicious_count == 0 and res.vt_total_vendors >= 50:
            positives.append(f"VT CLEAN → 0/{res.vt_total_vendors} security vendors flag this domain")
    
    # === HACKLINK / SEO SPAM ===
    if res.hacklink_detected:
        kw = res.hacklink_keywords.replace(";", ", ")[:80] if res.hacklink_keywords else "various"
        all_issues.append(f"🕷️ HACKLINK SEO SPAM DETECTED (keywords: {kw}) → Domain compromised with injected gambling/spam content")
    elif res.hacklink_keywords:
        kw = res.hacklink_keywords.replace(";", ", ")[:80]
        all_issues.append(f"HACKLINK KEYWORDS FOUND ({kw}) → Some hacklink-associated keywords present in page content")
    
    if res.hacklink_wp_compromised:
        all_issues.append("WORDPRESS COMPROMISED → WordPress files show signs of code injection/backdoor")
    
    if res.hacklink_vulnerable_plugins:
        plugins = res.hacklink_vulnerable_plugins.replace(";", ", ")[:80]
        all_issues.append(f"VULNERABLE WP PLUGINS ({plugins}) → Known exploitable plugins detected")
    
    if res.hacklink_spam_link_count >= 5:
        all_issues.append(f"SPAM LINKS ({res.hacklink_spam_link_count} hidden links) → Hidden outbound spam links injected into page")
    
    # === MALICIOUS SCRIPT / HIDDEN INJECTION (HIGH-VALUE SIGNALS) ===
    if res.hacklink_malicious_script:
        conf = res.hacklink_malicious_script_confidence
        signals = res.hacklink_malicious_script_signals.replace(";", ", ")[:100] if res.hacklink_malicious_script_signals else "unknown"
        if conf == "HIGH":
            all_issues.append(f"🚨 MALICIOUS SCRIPT INJECTION (HIGH confidence) → SocGholish/FakeUpdates-style obfuscated script detected; signals: {signals}")
        else:
            all_issues.append(f"⚠️ SUSPICIOUS SCRIPT DETECTED (MEDIUM confidence) → Potentially malicious script patterns found; signals: {signals}")
    
    if res.hacklink_hidden_injection:
        all_issues.append("🚨 HIDDEN CONTENT INJECTION → CSS-cloaked content (display:none, font-size:0) with links; classic hacklink/SEO spam technique")
    
    if res.hacklink_is_cpanel:
        all_issues.append("CPANEL HOSTING → cPanel shared hosting detected; frequently targeted in hacklink campaigns")
    
    if res.hacklink_suspicious_scripts:
        scripts = res.hacklink_suspicious_scripts.replace(";", ", ")[:120]
        all_issues.append(f"SUSPICIOUS EXTERNAL SCRIPTS ({scripts}) → Third-party scripts from known-bad or suspicious domains")
    
    # === TRANSFER LOCK / DOMAIN TAKEOVER ===
    if res.domain_transfer_lock_recent:
        days = res.whois_recently_updated_days
        all_issues.append(f"RECENT TRANSFER LOCK → Lock added recently ({days}d ago) on established domain — possible post-compromise lockdown by owner/registrar")
    
    if res.whois_recently_updated:
        days = res.whois_recently_updated_days
        all_issues.append(f"WHOIS RECENTLY UPDATED ({days}d ago) → Possible recent transfer, ownership change, or DNS hijack")
    
    # === EMPTY PAGE ===
    if res.is_empty_page:
        all_issues.append("EMPTY PAGE → Reachable domain returns empty/near-empty content; possibly parked, abandoned, or stripped post-compromise")
    
    # === CERTIFICATE TRANSPARENCY ===
    if res.ct_log_count == 0:
        all_issues.append("NO CT HISTORY → Zero certificates found in CT logs; domain may never have been used for HTTPS")
    elif res.ct_recent_issuance and res.domain_age_days > 365:
        all_issues.append(f"CT RECENT ISSUANCE ON OLD DOMAIN → New cert issued in last 7d on {res.domain_age_days}d-old domain; possible takeover/reactivation")
    elif res.ct_recent_issuance:
        all_issues.append("CT RECENT CERT ISSUANCE → Certificate issued within last 7 days")
    
    if res.ct_issuers:
        issuers = res.ct_issuers.replace(";", ", ")
        positives.append(f"CT issuers: {issuers}")
    
    # === EMAIL AUTHENTICATION ===
    if not res.dmarc_exists:
        all_issues.append("NO DMARC → Gmail/Yahoo now REQUIRE DMARC; expect 10-30% lower inbox placement")
    elif res.dmarc_policy == "none":
        all_issues.append("DMARC p=none → Zero spoofing protection; upgrade to p=quarantine or p=reject")
    
    if not res.dkim_exists:
        all_issues.append("NO DKIM → Missing cryptographic signature; 15-25% deliverability penalty")
    
    if not res.spf_exists:
        all_issues.append("NO SPF → Cannot verify authorized senders; emails may be rejected or spam-foldered")
    elif res.spf_mechanism == "~all":
        all_issues.append("SPF ~all (softfail) → Weak enforcement; upgrade to -all for strict rejection")
    elif res.spf_mechanism == "?all":
        all_issues.append("SPF ?all (neutral) → Provides zero protection; upgrade to -all")
    
    if res.dmarc_exists and not res.dmarc_rua:
        all_issues.append("DMARC NO REPORTING → Cannot monitor authentication failures; add rua= tag")
    
    # === INFRASTRUCTURE ===
    if not res.mx_exists:
        all_issues.append("NO MX RECORDS → Cannot receive bounces; some providers reject senders without MX")
    elif res.mx_is_null:
        all_issues.append("NULL MX RECORD → Domain explicitly cannot receive email")
    
    if res.mx_provider_type == "disposable":
        all_issues.append(f"DISPOSABLE MX PROVIDER ({res.mx_primary}) → Cheap/temporary email service commonly used for spam")
    elif res.mx_provider_type == "selfhosted":
        if res.mx_is_mail_prefix:
            all_issues.append(f"SELF-HOSTED MX ({res.mx_primary}) → mail.{{domain}} template pattern; common phishing infrastructure fingerprint")
        else:
            all_issues.append(f"SELF-HOSTED MX ({res.mx_primary}) → MX points to own domain; no external provider oversight")
    
    if not res.ptr_exists:
        all_issues.append("NO PTR RECORD → Corporate/enterprise email filters may reject")
    elif not res.ptr_matches_forward:
        all_issues.append("PTR MISMATCH → Forward/reverse DNS inconsistent; triggers spam filters")
    
    # v4.4: Specific TLS failure messages instead of generic "NO VALID HTTPS"
    if res.tls_handshake_failed:
        all_issues.append(f"TLS HANDSHAKE FAILED ({res.tls_error}) → Server rejects secure connections; broken SSL config or intentional evasion")
    elif res.tls_connection_failed:
        all_issues.append(f"TLS CONNECTION FAILED ({res.tls_error}) → Cannot reach port 443; no HTTPS service running")
    elif not res.https_valid:
        all_issues.append("NO VALID HTTPS → May indicate abandoned or suspicious domain")
    
    if res.is_suspicious_tld:
        all_issues.append("HIGH-ABUSE TLD → This domain extension faces extra spam scrutiny")
    
    if res.is_free_hosting:
        all_issues.append("FREE HOSTING PROVIDER → Associated with spam; limited reputation potential")
    
    if res.hosting_provider and res.hosting_provider_type in ("budget_shared", "free", "suspect", "platform"):
        type_labels = {
            "budget_shared": f"BUDGET SHARED HOST ({res.hosting_provider}) → Commonly used for spam/phishing; shared IP reputation risk",
            "free": f"FREE HOSTING ({res.hosting_provider}) → Associated with throwaway sites and spam campaigns",
            "suspect": f"SUSPECT HOST ({res.hosting_provider}) → Known bulletproof/abuse-tolerant hosting provider",
            "platform": f"DEV PLATFORM HOST ({res.hosting_provider}) → Developer platform with free tier; custom domains used for phishing infrastructure",
        }
        all_issues.append(type_labels.get(res.hosting_provider_type, f"HOSTING: {res.hosting_provider}"))
    
    if res.blocked_asn_org_match:
        all_issues.append(f"BLOCKED ASN ORG ({res.blocked_asn_org_match} / {res.hosting_asn_org}) → Domain hosted on blocked network; ASN {res.hosting_asn}")
    
    if res.is_free_email_domain:
        all_issues.append("FREE EMAIL PROVIDER DOMAIN → Cannot send bulk from consumer email domains")
    
    # === WEB/REDIRECT ISSUES ===
    if res.redirect_count >= 2:
        all_issues.append(f"REDIRECT CHAIN ({res.redirect_count} hops) → May trigger phishing detection")
    
    if res.redirect_cross_domain:
        all_issues.append("CROSS-DOMAIN REDIRECT → Suspicious pattern common in phishing")
    
    if res.redirect_uses_temp:
        all_issues.append("TEMP REDIRECTS (302/307) → Suggests URL cloaking; triggers filters")
    
    if res.is_minimal_shell:
        all_issues.append("MINIMAL/SHELL WEBSITE → Common phishing indicator")
    
    if res.has_js_redirect:
        all_issues.append("JAVASCRIPT REDIRECT → Suspicious redirect technique")
    
    if res.has_meta_refresh:
        all_issues.append("META REFRESH REDIRECT → Often used for cloaking")
    
    if res.has_external_js:
        all_issues.append("EXTERNAL JS LOADER → Content loaded from external source")
    
    if res.has_suspicious_iframe:
        all_issues.append("HIDDEN IFRAME → Often used to load malicious content")
    
    if res.is_parking_page:
        all_issues.append("PARKING PAGE → Domain not actively used")
    
    if res.form_posts_external:
        all_issues.append("FORM POSTS EXTERNALLY → Credentials sent to different domain")
    
    if res.has_sensitive_fields:
        all_issues.append("SENSITIVE FORM FIELDS → Requests SSN/card numbers")
    
    # === STATUS CODE SIGNALS (infrastructure intent) ===
    if res.has_401:
        all_issues.append("401 UNAUTHORIZED → Public domain requires authentication - unusual")
    
    if res.has_403:
        all_issues.append("403 FORBIDDEN → May be blocking scanners (cloaking)")
    
    if res.has_429:
        all_issues.append("429 RATE LIMITED → Throttling automated checks")
    
    if res.has_503:
        all_issues.append("503 UNAVAILABLE → Disposable/intermittent infrastructure")
    
    # === ACCESS RESTRICTION / TRUST SIGNALS (supplier fraud detection) ===
    if res.is_opaque_entity:
        all_issues.append("OPAQUE ENTITY → Access blocked AND no corporate pages found - high B2B fraud risk")
    elif res.is_access_restricted:
        all_issues.append(f"ACCESS RESTRICTED → {res.access_restriction_note}")
    
    if res.missing_trust_signals and not res.is_opaque_entity:
        all_issues.append("NO CORPORATE FOOTPRINT → Missing /about, /contact, /privacy pages")
    
    if res.has_credential_form and not res.brands_detected:
        all_issues.append("CREDENTIAL FORM DETECTED → Login form on landing page")
    
    # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
    if res.redirects_to_phishing_infra:
        all_issues.append(f"REDIRECTS TO PHISHING INFRASTRUCTURE ({res.phishing_infra_domain}) → Known malicious hosting")
    
    if res.has_doc_sharing_lure:
        all_issues.append(f"DOCUMENT SHARING LURE → '{res.doc_lure_found}' - Common phishing tactic")
    
    if res.has_phishing_js_behavior:
        all_issues.append(f"PHISHING KIT JS PATTERNS → Suspicious JavaScript: {res.phishing_js_patterns}")
    
    if res.has_email_in_url:
        all_issues.append(f"EMAIL TRACKING IN URL → {res.url_email_tracking} - Victim tracking technique")
    
    if res.has_hijack_path_pattern:
        all_issues.append(f"SUSPICIOUS URL PATH '/{res.hijack_path_found}/' → Common hijacked domain pattern")
    
    # === CUSTOM RULE LABELS ===
    if res.rules_labels:
        for label in res.rules_labels.split(';'):
            if label.strip():
                all_issues.append(f"RULE: {label.strip()}")
    
    # === POSITIVE SIGNALS ===
    if res.spf_exists and res.spf_mechanism == "-all":
        positives.append("Strict SPF (-all)")
    
    if res.dmarc_exists and res.dmarc_policy == "reject":
        positives.append("DMARC p=reject")
    elif res.dmarc_exists and res.dmarc_policy == "quarantine":
        positives.append("DMARC p=quarantine")
    
    if res.dkim_exists:
        positives.append("DKIM configured")
    
    if rdap_enabled and res.domain_age_days >= 365:
        years = res.domain_age_days // 365
        positives.append(f"Established ({years}+ years)")
    
    if res.https_valid:
        positives.append("Valid HTTPS")
    
    if res.bimi_exists:
        positives.append("BIMI verified")
    
    if res.mta_sts_exists:
        positives.append("MTA-STS enabled")
    
    if res.app_store_has_presence:
        is_platform_fp = res.hosting_provider_type == "platform"
        if res.app_store_confidence == "high":
            if is_platform_fp:
                # Don't show as positive — it's the platform's AASA, not the domain's
                pass
            else:
                methods = []
                if res.app_store_ios_verified:
                    methods.append("iOS deep links")
                if res.app_store_android_verified:
                    methods.append("Android deep links")
                if res.app_store_page_links:
                    methods.append("store links")
                if res.app_store_itunes_match:
                    methods.append("iTunes match")
                positives.append(f"App Store verified ({', '.join(methods)})")
        elif res.app_store_confidence == "medium":
            if not is_platform_fp:
                positives.append("App Store presence detected")
    elif res.app_store_confidence == "low":
        positives.append("Possible app store presence")
    
    if res.mx_exists and not res.mx_is_null:
        if res.mx_provider_type == "enterprise":
            positives.append("Enterprise MX (Google/Microsoft/Proofpoint)")
        else:
            positives.append("MX configured")
    
    if res.ptr_exists and res.ptr_matches_forward:
        positives.append("PTR matches")
    
    if res.trust_pages_found and len(res.trust_pages_found.split(';')) >= 2:
        positives.append(f"Corporate pages found ({len(res.trust_pages_found.split(';'))})")
    
    # === BUILD SUMMARY ===
    # Score each issue by its config weight for filtering and sorting.
    # Issues whose corresponding signal has weight=0 (disabled) are excluded.
    # Remaining issues sort highest-weight-first so the top 3 are the most critical.
    
    def _issue_weight(text):
        """Map issue text to its config weight for sorting/filtering."""
        # Ordered by severity — first match wins
        _map = [
            ('HIGH-RISK PHISHING INFRA', 100),
            ('MALICIOUS SCRIPT INJECTION (HIGH', weights.get('malicious_script', 100)),
            ('SUSPICIOUS SCRIPT DETECTED (MEDIUM', weights.get('malicious_script_medium', 25)),
            ('VT MALICIOUS', weights.get('vt_malicious_high', 65)),
            ('HIDDEN CONTENT INJECTION', weights.get('hidden_injection', 55)),
            ('BLACKLISTED DOMAIN', weights.get('domain_blacklisted', 50)),
            ('HACKLINK SEO SPAM DETECTED', weights.get('hacklink_detected', 50)),
            ('WORDPRESS COMPROMISED', weights.get('hacklink_wp_compromised', 45)),
            ('BLACKLISTED IP', weights.get('ip_blacklisted', 40)),
            ('SPF +all', weights.get('spf_pass_all', 40)),
            ('DOMAIN CREATED TODAY', weights.get('domain_age_0d', 40)),
            ('SPAM LINKS', weights.get('hacklink_spam_links', 35)),
            ('DISPOSABLE EMAIL', weights.get('disposable_domain', 35)),
            ('TYPOSQUAT', weights.get('typosquat', 30)),
            ('BRAND + SPOOFING', weights.get('brand_keyword_domain', 30)),
            ('DOMAIN IMPERSONATES', weights.get('domain_brand_impersonation', 25)),
            ('MALWARE LINKS', weights.get('malware_links', 25)),
            ('CREDENTIAL FORM + BRAND', 25),
            ('VULNERABLE WP PLUGINS', weights.get('hacklink_vulnerable_plugins', 25)),
            ('DOMAIN ONLY', weights.get('domain_age_7d', 25)),
            ('REDIRECTS TO PHISHING', weights.get('redirects_phishing', 25)),
            ('VT FLAGGED', weights.get('vt_malicious_medium', 40)),
            ('BLOCKED ASN', weights.get('blocked_asn', 20)),
            ('OPAQUE ENTITY', weights.get('opaque_entity', 20)),
            ('TLD VARIANT SPOOF', weights.get('tld_variant', 20)),
            ('EMPTY PAGE', weights.get('empty_page', 20)),
            ('ZERO EMAIL AUTH', 20),
            ('HACKLINK KEYWORDS', weights.get('hacklink_keywords', 15)),
            ('SUSPICIOUS PREFIX', weights.get('suspicious_prefix', 15)),
            ('SUSPICIOUS SUFFIX', weights.get('suspicious_suffix', 15)),
            ('VT SUSPICIOUS', weights.get('vt_suspicious', 15)),
            ('FREE EMAIL PROVIDER', weights.get('free_email_domain', 15)),
            ('DOCUMENT SHARING LURE', weights.get('doc_lure', 15)),
            ('PHISHING KIT JS', weights.get('phishing_js', 15)),
            ('TRANSFER LOCK', weights.get('transfer_lock_recent', 15)),
            ('CT RECENT ISSUANCE ON OLD', weights.get('ct_recent_issuance', 8)),
            ('NO CT HISTORY', weights.get('ct_no_history', 12)),
            ('SENSITIVE FORM', weights.get('sensitive_fields', 12)),
            ('TECH SUPPORT SCAM TLD', weights.get('tech_support_tld', 12)),
            ('DISPOSABLE MX', weights.get('disposable_mx', 12)),
            ('HIJACK', weights.get('hijack_path', 12)),
            ('RETAIL SCAM TLD', weights.get('retail_scam_tld', 10)),
            ('CROSS-DOMAIN BRAND', weights.get('cross_domain_brand_link', 12)),
            ('NO DMARC', weights.get('no_dmarc', 10)),
            ('WHOIS RECENTLY UPDATED', weights.get('whois_recently_updated', 10)),
            ('ACCESS RESTRICTED', weights.get('access_restricted', 10)),
            ('FREE HOSTING', weights.get('free_hosting', 10)),
            ('PARKING PAGE', weights.get('parking_page', 10)),
            ('CREDENTIAL FORM DETECTED', weights.get('credential_form', 10)),
            ('E-COMMERCE WITHOUT', 10),
            ('EMAIL TRACKING', weights.get('email_in_url', 10)),
            ('TLS HANDSHAKE FAILED', 10),
            ('TLS CONNECTION FAILED', 10),
            ('BRAND IMPERSONATION', weights.get('brand_impersonation', 15)),
            ('DOMAIN', 8),  # domain age 30-90d fallback
            ('NO SPF', weights.get('no_spf', 8)),
            ('SELF-HOSTED MX', weights.get('selfhosted_mx', 8)),
            ('CROSS-DOMAIN REDIRECT', weights.get('redirect_cross_domain', 8)),
            ('MINIMAL/SHELL', weights.get('minimal_shell', 8)),
            ('JAVASCRIPT REDIRECT', weights.get('js_redirect', 8)),
            ('HIDDEN IFRAME', weights.get('suspicious_iframe', 8)),
            ('NO MX', weights.get('no_mx', 8)),
            ('CPANEL HOSTING', weights.get('cpanel_detected', 8)),
            ('BUDGET SHARED HOST', weights.get('hosting_budget_shared', 8)),
            ('SUSPECT HOST', 8),
            ('DEV PLATFORM HOST', 8),
            ('NO VALID HTTPS', 7),
            ('HIGH-ABUSE TLD', weights.get('suspicious_tld', 6)),
            ('NO DKIM', weights.get('no_dkim', 6)),
            ('REDIRECT CHAIN', weights.get('redirect_chain_2plus', 5)),
            ('DMARC p=none', weights.get('dmarc_p_none', 5)),
            ('SPF ?all', weights.get('spf_neutral_all', 5)),
            ('TEMP REDIRECTS', weights.get('redirect_temp', 5)),
            ('META REFRESH', weights.get('meta_refresh', 5)),
            ('EXTERNAL JS LOADER', weights.get('external_js', 5)),
            ('PTR MISMATCH', weights.get('ptr_mismatch', 5)),
            ('BLACKLIST CHECK INCONCLUSIVE', 5),
            ('401 UNAUTHORIZED', 5),
            ('403 FORBIDDEN', 5),
            ('429 RATE LIMITED', 5),
            ('503 UNAVAILABLE', 5),
            ('NO PTR', weights.get('no_ptr', 3)),
            ('SPF ~all', weights.get('spf_softfail_all', 2)),
            ('DMARC NO REPORTING', weights.get('dmarc_no_rua', 2)),
            ('NO CORPORATE FOOTPRINT', weights.get('missing_trust', 8)),
            ('SUSPICIOUS EXTERNAL SCRIPTS', 0),  # Not a scored signal — informational only
            ('VT THREAT NAMES', 0),  # Informational detail, not a risk signal
            ('CT RECENT CERT ISSUANCE', 3),  # Minor standalone
        ]
        for prefix, w in _map:
            if prefix in text:
                return w
        return 5  # Default for RULE: labels and unmapped issues
    
    # Score, filter zeros, sort by weight descending
    scored_issues = [((_issue_weight(t), t)) for t in all_issues]
    scored_issues = [(w, t) for w, t in scored_issues if w > 0]
    scored_issues.sort(key=lambda x: x[0], reverse=True)
    
    parts = []
    
    # High-risk phishing infra flag (most important — show first)
    if res.high_risk_phish_infra:
        parts.append(f"🚨 HIGH-RISK PHISHING INFRA → {res.high_risk_phish_infra_reason}")
    
    # Recommendation with score
    if res.recommendation == "DENY":
        parts.append(f"⛔ DENY (Score: {res.risk_score})")
    else:
        parts.append(f"✅ APPROVE (Score: {res.risk_score})")
    
    # Top issues only (limit to 3 most important by weight)
    if scored_issues:
        top_issues = [text for _, text in scored_issues[:3]]
        parts.append(" • ".join(top_issues))
        remaining = len(scored_issues) - 3
        if remaining > 0:
            parts.append(f"+{remaining} more issues")
    
    # Positive signals (compact)
    if positives:
        parts.append("✓ " + ", ".join(positives))
    
    return " | ".join(parts)


def calculate_score(res: DomainApprovalResult, config: dict) -> None:
    score = 0
    signals: Set[str] = set()
    breakdown: dict = {}  # signal_or_rule → points contributed
    weights = config.get('weights', DEFAULT_CONFIG['weights'])
    threshold = config.get('approve_threshold', 50)
    
    def add(signal: str, points: int):
        """Record a signal, its points, and accumulate score."""
        nonlocal score
        signals.add(signal)
        if points != 0:
            breakdown[signal] = breakdown.get(signal, 0) + points
            score += points
    
    # Email Auth - these are DELIVERABILITY concerns only, NOT fraud signals
    # A domain missing these should get warnings, not denial
    if not res.spf_exists:
        add("no_spf", weights.get('no_spf', 8))
    else:
        if res.spf_mechanism == "+all":
            add("spf_pass_all", weights.get('spf_pass_all', 40))  # This IS a security issue - allows spoofing
        elif res.spf_mechanism == "?all":
            add("spf_neutral_all", weights.get('spf_neutral_all', 5))
        elif res.spf_mechanism == "~all":
            add("spf_softfail_all", weights.get('spf_softfail_all', 2))  # Very minor - this is common and acceptable
    if not res.dkim_exists:
        add("no_dkim", weights.get('no_dkim', 6))
    
    if not res.dmarc_exists:
        add("no_dmarc", weights.get('no_dmarc', 10))
    else:
        if res.dmarc_policy == "none":
            add("dmarc_p_none", weights.get('dmarc_p_none', 5))
        if not res.dmarc_rua:
            add("dmarc_no_rua", weights.get('dmarc_no_rua', 2))
    
    if not res.mx_exists:
        add("no_mx", weights.get('no_mx', 8))
    elif res.mx_is_null:
        add("null_mx", weights.get('null_mx', 12))
    
    # MX provider type scoring (v4.7)
    if res.mx_provider_type == "enterprise":
        add("mx_enterprise", weights.get('mx_enterprise_bonus', -5))
    elif res.mx_provider_type == "disposable":
        add("mx_disposable", weights.get('mx_disposable', 10))
    elif res.mx_provider_type == "selfhosted":
        add("mx_selfhosted", weights.get('mx_selfhosted', 6))
    
    # mail.{domain} template fingerprint — stronger than generic selfhosted
    # This exact pattern is used by phishing infrastructure toolkits
    if res.mx_is_mail_prefix:
        add("mx_mail_prefix", weights.get('mx_mail_prefix', 4))
    
    # SPF exists but has NO external email provider includes
    # Legit businesses almost always include Google/Microsoft/SendGrid/etc.
    # Self-only SPF (just a/mx mechanisms) = no real email provider
    if res.spf_exists and not res.spf_has_external_includes:
        add("spf_no_external_includes", weights.get('spf_no_external_includes', 3))
    
    if not res.ptr_exists:
        add("no_ptr", weights.get('no_ptr', 4))
    elif not res.ptr_matches_forward:
        add("ptr_mismatch", weights.get('ptr_mismatch', 5))
    
    if res.bimi_exists:
        add("has_bimi", weights.get('has_bimi', -8))
    if res.mta_sts_exists:
        add("has_mta_sts", weights.get('has_mta_sts', -5))
    
    # === APP STORE PRESENCE BONUS (Legitimacy Signal) ===
    # Tiered by confidence: high (verified deep links) > medium (page links/API) > low (keyword only)
    # IMPORTANT: Platform hosting providers (Render, Netlify, Vercel, etc.) serve their OWN
    # AASA/asset-links files for ALL custom domains. A domain on Render getting "iOS deep links"
    # is detecting Render's app, not the domain owner's app. Suppress the bonus in this case.
    is_platform_hosted = res.hosting_provider_type == "platform"
    if res.app_store_has_presence:
        if res.app_store_confidence == "high":
            if is_platform_hosted:
                # Platform's AASA, not the domain's — don't give bonus
                add("app_store_platform_false_positive", 0)
            else:
                add("app_store_high", weights.get('app_store_high', -15))
        elif res.app_store_confidence == "medium":
            if not is_platform_hosted:
                add("app_store_medium", weights.get('app_store_medium', -10))
        elif res.app_store_confidence == "low":
            # v6.2: Fixed indentation — was incorrectly attached to outer if
            add("app_store_low", weights.get('app_store_low', -3))
    
    # Blacklists - HIGH weight, these are real fraud signals
    if res.domain_blacklist_count > 0:
        add("domain_blacklisted", weights.get('domain_blacklisted', 40) * min(res.domain_blacklist_count, 3))
    if res.ip_blacklist_count > 0:
        add("ip_blacklisted", weights.get('ip_blacklisted', 35) * min(res.ip_blacklist_count, 3))
    
    # v6.2: Inconclusive blacklist checks — "we don't know" ≠ "clean"
    # Apply a moderate penalty so these don't silently pass
    if res.domain_blacklist_inconclusive > 0:
        add("blacklist_inconclusive", weights.get('blacklist_inconclusive', 15))
    if res.ip_blacklist_inconclusive > 0:
        add("blacklist_inconclusive", weights.get('blacklist_inconclusive', 15))
    
    # Blocked ASN organizations - instant high score
    blocked_asn_orgs = config.get('blocked_asn_orgs', [])
    if res.hosting_asn_org and blocked_asn_orgs:
        asn_org_lower = res.hosting_asn_org.lower()
        matched_asn = next((org for org in blocked_asn_orgs if org.lower() in asn_org_lower), None)
        if matched_asn:
            asn_score = config.get('blocked_asn_org_score', 100)
            add("blocked_asn_org", asn_score)
            res.blocked_asn_org_match = matched_asn  # Store for display
    
    # Domain age
    if res.domain_age_days >= 0:
        if res.domain_age_days <= 1:
            res.domain_created_today = True
            add("domain_created_today", weights.get('domain_created_today', 50))
        if res.domain_age_days < 7:
            add("domain_lt_7d", weights.get('domain_lt_7d', 35))
        if res.domain_age_days < 30:
            add("domain_lt_30d", weights.get('domain_lt_30d', 12))
        elif res.domain_age_days < 90:
            add("domain_lt_90d", weights.get('domain_lt_90d', 5))
        # Track established domains (for rule detection)
        if res.domain_age_days >= 365:
            add("domain_gt_1yr", 0)
    
    # Domain type
    if res.is_suspicious_tld:
        add("suspicious_tld", weights.get('suspicious_tld', 12))
    if res.is_free_email_domain:
        add("free_email_domain", weights.get('free_email_domain', 20))
    if res.is_disposable_email:
        add("disposable_email", weights.get('disposable_email', 30))
    if res.typosquat_target:
        add("typosquat_detected", weights.get('typosquat_detected', 25))
    if res.is_free_hosting:
        add("free_hosting", weights.get('free_hosting', 12))
    
    # === HOSTING PROVIDER DETECTION ===
    if res.hosting_provider_type == "budget_shared":
        add("hosting_budget_shared", weights.get('hosting_budget_shared', 8))
    elif res.hosting_provider_type == "free":
        add("hosting_free", weights.get('hosting_free', 12))
    elif res.hosting_provider_type == "suspect":
        add("hosting_suspect", weights.get('hosting_suspect', 18))
    elif res.hosting_provider_type == "platform":
        # Dev platforms (Render, Netlify, Vercel) aren't inherently bad,
        # but custom domains on free-tier platforms sending email is a red flag
        add("hosting_platform", weights.get('hosting_platform', 4))
    
    # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
    if res.has_suspicious_prefix:
        add("suspicious_prefix", weights.get('suspicious_prefix', 15))
    if res.has_suspicious_suffix:
        add("suspicious_suffix", weights.get('suspicious_suffix', 15))
    if res.is_tech_support_tld:
        add("tech_support_tld", weights.get('tech_support_tld', 18))
    if res.domain_impersonates_brand:
        add("domain_brand_impersonation", weights.get('domain_brand_impersonation', 25))
    
    # Brand + spoofing keyword: easyjetconnect, amazonverify, chaselogin, etc.
    # This is a much stronger signal than brand name alone — it specifically
    # mimics legitimate brand service names/subdomains
    if res.brand_plus_keyword_domain:
        add("brand_spoofing_keyword", weights.get('brand_spoofing_keyword', 20))
    
    # === TLD VARIANT SPOOFING DETECTION ===
    if res.tld_variant_detected:
        add("tld_variant_spoofing", weights.get('tld_variant_spoofing', 30))
    
    # E-commerce / Retail scam indicators
    if res.is_retail_scam_tld:
        add("retail_scam_tld", weights.get('retail_scam_tld', 12))
    if res.has_cross_domain_brand_link:
        add("cross_domain_brand_link", weights.get('cross_domain_brand_link', 18))
    if res.is_ecommerce_site and res.missing_business_identity:
        add("ecommerce_no_identity", weights.get('ecommerce_no_identity', 15))
    
    # Web/TLS
    if not res.https_valid:
        add("no_https", weights.get('no_https', 25))
    
    # v4.4: Specific TLS failure scoring (adds ON TOP of no_https)
    if res.tls_handshake_failed:
        add("tls_handshake_failed", weights.get('tls_handshake_failed', 20))
    if res.tls_connection_failed:
        add("tls_connection_failed", weights.get('tls_connection_failed', 8))
    
    if res.cert_expired:
        add("cert_expired", weights.get('cert_expired', 15))
    if res.cert_self_signed:
        add("cert_self_signed", weights.get('cert_self_signed', 12))
    
    # Redirects
    if res.redirect_count >= 2:
        add("redirect_chain_2plus", weights.get('redirect_chain_2plus', 12))
    if res.redirect_cross_domain:
        add("redirect_cross_domain", weights.get('redirect_cross_domain', 12))
    if res.redirect_uses_temp:
        add("redirect_temp_302_307", weights.get('redirect_temp_302_307', 10))
    
    # === STATUS CODE SIGNALS (per research: high-value early indicators) ===
    # 401 = unauthorized on public site - unusual
    if res.has_401:
        add("status_401_unauthorized", weights.get('status_401_unauthorized', 12))
    
    # 403 = cloaking/scanner blocking - VERY strong signal
    if res.has_403:
        add("status_403_cloaking", weights.get('status_403_cloaking', 15))
    
    # 429 = throttling scanners - medium signal
    if res.has_429:
        add("status_429_throttling", weights.get('status_429_throttling', 8))
    
    # 503 = disposable infrastructure - medium signal  
    if res.has_503:
        add("status_503_disposable", weights.get('status_503_disposable', 8))
    
    # === ACCESS RESTRICTION / CORPORATE TRUST SIGNALS ===
    # Access restricted (401 or 403) on what should be a public domain
    if res.is_access_restricted:
        add("access_restricted", weights.get('access_restricted', 10))
    
    # Missing trust signals (no about/contact pages)
    # Don't flag on empty pages — obviously an empty page has no /about etc.
    if res.missing_trust_signals and not res.is_empty_page:
        add("missing_trust_signals", weights.get('missing_trust_signals', 8))
    
    # Opaque entity - access blocked AND no corporate footprint
    # This is a classic B2B fraud / supplier impersonation pattern
    if res.is_opaque_entity and not res.is_empty_page:
        add("opaque_entity", weights.get('opaque_entity', 20))
    
    # Content
    if res.is_minimal_shell and not res.is_empty_page:
        add("minimal_shell", weights.get('minimal_shell', 15))
    if res.has_js_redirect:
        add("js_redirect", weights.get('js_redirect', 12))
    if res.has_meta_refresh:
        add("meta_refresh", weights.get('meta_refresh', 5))
    if res.has_external_js:
        add("external_js_loader", weights.get('external_js_loader', 6))
    if res.has_suspicious_iframe:
        add("suspicious_iframe", weights.get('suspicious_iframe', 8))
    if res.is_parking_page:
        add("parking_page", weights.get('parking_page', 6))
    if res.has_credential_form:
        add("credential_form", weights.get('credential_form', 20))
    if res.has_sensitive_fields:
        add("sensitive_fields", weights.get('sensitive_fields', 10))
    if res.form_posts_external:
        add("form_posts_external", weights.get('form_posts_external', 10))
    if res.brands_detected:
        add("brand_impersonation", weights.get('brand_impersonation', 22))
    if res.phishing_paths_found:
        add("phishing_paths", weights.get('phishing_paths', 20))
    if res.malware_links_found:
        add("malware_links", weights.get('malware_links', 25))
    
    # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
    if res.has_hijack_path_pattern:
        add("hijack_path_pattern", weights.get('hijack_path_pattern', 12))
    if res.has_doc_sharing_lure:
        add("doc_sharing_lure", weights.get('doc_sharing_lure', 15))
    if res.has_phishing_js_behavior:
        add("phishing_js_behavior", weights.get('phishing_js_behavior', 18))
    if res.redirects_to_phishing_infra:
        add("phishing_infra_redirect", weights.get('phishing_infra_redirect', 25))
    if res.has_email_in_url:
        add("email_tracking_url", weights.get('email_tracking_url', 20))
    
    # === VIRUSTOTAL REPUTATION SCORING ===
    if res.vt_available:
        mal = res.vt_malicious_count
        sus = res.vt_suspicious_count
        if mal >= 5:
            add("vt_malicious_high", weights.get('vt_malicious_high', 65))
        elif mal >= 3:
            add("vt_malicious_medium", weights.get('vt_malicious_medium', 40))
        elif mal >= 1:
            add("vt_malicious_low", weights.get('vt_malicious_low', 22))
        
        if sus >= 3:
            add("vt_suspicious", weights.get('vt_suspicious', 15))
        elif sus >= 1:
            add("vt_suspicious_low", weights.get('vt_suspicious_low', 5))
        
        if res.vt_community_score < -5:
            add("vt_negative_community", weights.get('vt_negative_community', 10))
        
        if mal == 0 and sus == 0 and res.vt_total_vendors >= 50:
            add("vt_clean", weights.get('vt_clean', -5))
    
    # === HACKLINK / SEO SPAM SCORING ===
    if res.hacklink_detected:
        add("hacklink_detected", weights.get('hacklink_detected', 50))
    
    if res.hacklink_keywords and not res.hacklink_detected:
        # Keywords found but below threshold — still a warning signal
        kw_count = len(res.hacklink_keywords.split(";")) if res.hacklink_keywords else 0
        if kw_count >= 1:
            add("hacklink_keywords", weights.get('hacklink_keywords', 15))
    
    if res.hacklink_wp_compromised:
        add("hacklink_wp_compromised", weights.get('hacklink_wp_compromised', 45))
    
    if res.hacklink_vulnerable_plugins:
        add("hacklink_vulnerable_plugins", weights.get('hacklink_vulnerable_plugins', 25))
    
    if res.hacklink_spam_link_count >= 5:
        add("hacklink_spam_links", weights.get('hacklink_spam_links', 35))
    
    # === MALICIOUS SCRIPT INJECTION (SocGholish/FakeUpdates/obfuscated) ===
    # v7.2: Multi-signal confidence — HIGH gets full weight, MEDIUM gets reduced weight
    if res.hacklink_malicious_script:
        if res.hacklink_malicious_script_confidence == "HIGH":
            add("malicious_script", weights.get('malicious_script', 100))
        elif res.hacklink_malicious_script_confidence == "MEDIUM":
            add("malicious_script", weights.get('malicious_script_medium', 25))
    
    # === HIDDEN CONTENT INJECTION (CSS cloaking: display:none, font-size:0) ===
    if res.hacklink_hidden_injection:
        add("hidden_injection", weights.get('hidden_injection', 55))
    
    # === CPANEL HOSTING DETECTED ===
    if res.hacklink_is_cpanel:
        add("cpanel_detected", weights.get('cpanel_detected', 8))
    
    # === TRANSFER LOCK / WHOIS ENRICHMENT ===
    if res.domain_transfer_lock_recent:
        add("transfer_lock_recent", weights.get('transfer_lock_recent', 15))
    
    if res.whois_recently_updated:
        add("whois_recently_updated", weights.get('whois_recently_updated', 10))
    
    # === EMPTY PAGE ===
    if res.is_empty_page:
        add("empty_page", weights.get('empty_page', 20))
    
    # === CERTIFICATE TRANSPARENCY ===
    if res.ct_recent_issuance:
        add("ct_recent_issuance", weights.get('ct_recent_issuance', 10))
    
    if res.ct_log_count == 0:
        add("ct_no_history", weights.get('ct_no_history', 15))
    
    # === UNIFIED RULES ENGINE ===
    # All scoring logic beyond base weights (former combos + custom rules)
    # Rules support if/then/else logic:
    #   if_all:  ALL listed signals must be present (AND)
    #   if_any:  AT LEAST ONE listed signal must be present (OR)
    #   if_not:  NONE of these signals may be present (exclusion)
    #   score:   points to add (positive = riskier, negative = safer)
    rules = config.get('rules', DEFAULT_CONFIG.get('rules', []))
    rules_hit = []
    rules_labels = []
    for rule in rules:
        rule_name = rule.get('name', 'unnamed_rule')
        
        # Skip disabled rules
        if not rule.get('enabled', True):
            continue
        
        # Check if_all: every signal in this list must be present
        if_all = rule.get('if_all', [])
        if if_all and not all(s in signals for s in if_all):
            continue
        
        # Check if_any: at least one signal in this list must be present
        if_any = rule.get('if_any', [])
        if if_any and not any(s in signals for s in if_any):
            continue
        
        # Check if_not: none of these signals may be present
        if_not = rule.get('if_not', [])
        if if_not and any(s in signals for s in if_not):
            continue
        
        # All conditions met — rule fires
        rule_score = rule.get('score', 0)
        rule_label = rule.get('label', '')
        if rule_score != 0:
            breakdown[f"rule:{rule_name}"] = rule_score
            score += rule_score
        rules_hit.append(rule_name)
        if rule_label:
            rules_labels.append(rule_label)
    
    res.risk_score = max(0, min(score, 100))
    
    bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
    res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
    
    res.recommendation = "APPROVE" if res.risk_score <= threshold else "DENY"
    res.signals_triggered = ";".join(sorted(signals))
    res.combos_triggered = ""  # Deprecated: combos are now unified rules
    res.rules_triggered = ";".join(rules_hit)
    res.rules_labels = ";".join(rules_labels)
    res.score_breakdown = json.dumps(breakdown)
    
    # === BUILD ASN DISPLAY STRING ===
    if res.hosting_asn and res.hosting_asn_org:
        res.asn_display = f"AS{res.hosting_asn} ({res.hosting_asn_org})"
    elif res.hosting_asn:
        res.asn_display = f"AS{res.hosting_asn}"
    elif res.hosting_asn_org:
        res.asn_display = res.hosting_asn_org
    
    # === HIGH-RISK PHISHING INFRASTRUCTURE COMPOSITE CHECK ===
    # Fires when ALL of these are true:
    #   1. Render ASN (or blocked ASN match for Render)
    #   2. Self-hosted MX
    #   3. phish_factory_template rule fired
    #   4. platform_phish_setup rule fired
    # This combination is the exact fingerprint of the Swedish invoice phish population.
    rules_hit_names = rules_hit
    is_render = (
        (res.hosting_provider and res.hosting_provider.lower() == "render")
        or (res.hosting_asn_org and "render" in res.hosting_asn_org.lower())
        or (res.blocked_asn_org_match and "render" in res.blocked_asn_org_match.lower())
    )
    has_selfhosted_mx = "mx_selfhosted" in signals
    has_phish_factory = "phish_factory_template" in rules_hit_names
    has_platform_phish = "platform_phish_setup" in rules_hit_names
    
    if is_render and has_selfhosted_mx and has_phish_factory and has_platform_phish:
        res.high_risk_phish_infra = True
        res.high_risk_phish_infra_reason = (
            "Render ASN + self-hosted MX + phishing factory template + platform phish setup — "
            "matches known Swedish invoice phishing infrastructure fingerprint"
        )
    elif is_render and has_selfhosted_mx and (has_phish_factory or has_platform_phish):
        # Partial match — still very suspicious
        res.high_risk_phish_infra = True
        matched = []
        if has_phish_factory:
            matched.append("phish_factory_template")
        if has_platform_phish:
            matched.append("platform_phish_setup")
        res.high_risk_phish_infra_reason = (
            f"Render ASN + self-hosted MX + {' + '.join(matched)} — "
            "partial match on known phishing infrastructure fingerprint"
        )
    
    res.summary = generate_summary(res, signals, res.domain_age_days >= 0, weights=weights)


# ============================================================================
# MAIN ANALYSIS FUNCTION
# ============================================================================

def analyze_domain(domain: str, timeout: float = 10.0, check_rdap: bool = True,
                   weights: dict = None, threshold: int = 50,
                   full_config: dict = None) -> dict:
    """
    Main entry point for domain analysis.
    Returns dict with all results.
    
    If full_config is provided, rules, allowlists, and other settings are
    taken from it.  Otherwise falls back to DEFAULT_CONFIG (all rules enabled).
    """
    src = full_config or {}
    config = {
        'weights': weights or src.get('weights', DEFAULT_CONFIG['weights']),
        'approve_threshold': threshold,
        'rules': src.get('rules', DEFAULT_CONFIG.get('rules', [])),
        'suspicious_tlds': src.get('suspicious_tlds', DEFAULT_CONFIG.get('suspicious_tlds', [])),
        'protected_brands': src.get('protected_brands', DEFAULT_CONFIG.get('protected_brands', [])),
        'disposable_domains': src.get('disposable_domains', DEFAULT_CONFIG.get('disposable_domains', [])),
        'domain_blacklists': src.get('domain_blacklists', DEFAULT_CONFIG.get('domain_blacklists', [])),
        'ip_blacklists': src.get('ip_blacklists', DEFAULT_CONFIG.get('ip_blacklists', [])),
        'hosting_providers': src.get('hosting_providers', DEFAULT_CONFIG.get('hosting_providers', {})),
        'tld_variant_allowlist': src.get('tld_variant_allowlist', DEFAULT_CONFIG.get('tld_variant_allowlist', [])),
        'spoofing_allowlist': src.get('spoofing_allowlist', DEFAULT_CONFIG.get('spoofing_allowlist', [])),
        'blocked_asn_orgs': src.get('blocked_asn_orgs', DEFAULT_CONFIG.get('blocked_asn_orgs', [])),
        'blocked_asn_org_score': src.get('blocked_asn_org_score', DEFAULT_CONFIG.get('blocked_asn_org_score', 100)),
    }
    
    res = DomainApprovalResult(domain=domain)
    res.scan_timestamp = datetime.now(timezone.utc).isoformat()
    
    # DNS Resolution
    try:
        res.ip_address = socket.gethostbyname(domain)
        res.resolved = True
    except:
        res.recommendation = "DENY"
        res.summary = "DENY: Domain does not resolve"
        res.risk_level = "ERROR"
        res.risk_score = 100
        return asdict(res)
    
    # PTR
    res.ptr_exists, res.ptr_record, res.ptr_matches_forward = get_ptr_record(res.ip_address)
    
    # Domain characteristics
    domain_lower = domain.lower()
    res.is_suspicious_tld = any(domain_lower.endswith(t) for t in config['suspicious_tlds'])
    res.is_retail_scam_tld = any(domain_lower.endswith(t) for t in RETAIL_SCAM_TLDS)
    res.is_free_email_domain = domain_lower in FREE_EMAIL_PROVIDERS
    res.is_free_hosting = any(p in domain_lower for p in FREE_HOSTING_PATTERNS)
    res.is_url_shortener = domain_lower in URL_SHORTENERS
    res.is_disposable_email = is_disposable_email(domain_lower, config['disposable_domains'])
    res.typosquat_target, res.typosquat_similarity = check_typosquatting(domain, config['protected_brands'])
    
    # Check domain name for tech support scam / brand impersonation patterns
    domain_patterns = check_domain_name_patterns(domain, config)
    res.has_suspicious_prefix = domain_patterns["has_suspicious_prefix"]
    res.suspicious_prefix_found = domain_patterns["suspicious_prefix"]
    res.has_suspicious_suffix = domain_patterns["has_suspicious_suffix"]
    res.suspicious_suffix_found = domain_patterns["suspicious_suffix"]
    res.is_tech_support_tld = domain_patterns["is_tech_support_tld"]
    res.domain_impersonates_brand = domain_patterns["domain_impersonates_brand"]
    res.brand_spoofing_keyword = domain_patterns["brand_spoofing_keyword"]
    res.brand_plus_keyword_domain = domain_patterns["brand_plus_keyword"]
    res.domain_pattern_risk = ";".join(domain_patterns["patterns_found"])
    
    # Spoofing allowlist: suppress typosquat, brand impersonation, prefix/suffix
    # signals for domains explicitly cleared by admin review
    spoofing_allowlist = [d.lower().strip() for d in config.get('spoofing_allowlist', [])]
    if domain_lower in spoofing_allowlist or any(domain_lower.endswith('.' + a) for a in spoofing_allowlist):
        res.typosquat_target = ""
        res.typosquat_similarity = 0.0
        res.has_suspicious_prefix = False
        res.suspicious_prefix_found = ""
        res.has_suspicious_suffix = False
        res.suspicious_suffix_found = ""
        res.domain_impersonates_brand = ""
        res.brand_spoofing_keyword = ""
        res.brand_plus_keyword_domain = False
        res.domain_pattern_risk = ""
    
    # SPF
    spf_record, spf_exists, spf_parsed = get_spf(domain)
    res.spf_record = spf_record[:500]
    res.spf_exists = spf_exists
    if spf_exists:
        res.spf_mechanism = spf_parsed.get("mechanism", "")
        res.spf_includes = ";".join(spf_parsed.get("includes", []))
        res.spf_lookup_count = spf_parsed.get("lookups", 0)
        res.spf_syntax_valid = spf_parsed.get("valid", True)
        # Check if SPF includes any real external email provider
        KNOWN_SPF_PROVIDERS = [
            '_spf.google.com', 'google.com', 'googlemail.com',
            'spf.protection.outlook.com', 'outlook.com', 'microsoft.com',
            'amazonses.com', 'sendgrid.net', 'mailgun.org', 'mandrillapp.com',
            'mailchimp.com', 'postmarkapp.com', 'sparkpostmail.com',
            'zoho.com', 'zoho.eu', 'fastmail.com', 'messagingengine.com',
            'icloud.com', 'apple.com', 'protonmail.ch',
            'mimecast.com', 'pphosted.com', 'fireeyecloud.com',
            'secureserver.net', 'emailsrvr.com', 'hostinger.com',
            'ovh.net', 'gandi.net', 'ionos.com',
        ]
        includes_list = spf_parsed.get("includes", [])
        res.spf_has_external_includes = any(
            any(provider in inc.lower() for provider in KNOWN_SPF_PROVIDERS)
            for inc in includes_list
        )
    
    # DKIM
    res.dkim_exists, dkim_selectors = check_dkim(domain)
    res.dkim_selectors_found = ";".join(dkim_selectors)
    
    # DMARC
    dmarc_record, dmarc_exists, dmarc_parsed = get_dmarc(domain)
    res.dmarc_record = dmarc_record[:500]
    res.dmarc_exists = dmarc_exists
    if dmarc_exists:
        res.dmarc_policy = dmarc_parsed.get("policy", "")
        res.dmarc_pct = dmarc_parsed.get("pct", 100)
        res.dmarc_rua = dmarc_parsed.get("rua", "")
    
    # MX
    res.mx_exists, mx_records, res.mx_is_null = get_mx(domain)
    if mx_records:
        res.mx_records = ";".join([f"{p}:{h}" for p, h in mx_records])
        res.mx_primary = mx_records[0][1] if mx_records else ""
        free_mx = ['google.com', 'googlemail.com', 'yahoodns', 'outlook.com']
        res.mx_uses_free_provider = any(f in res.mx_primary.lower() for f in free_mx)
        res.mx_provider_type = classify_mx_provider(mx_records, domain, config)
        # Detect mail.{domain} template fingerprint — common in phishing infrastructure
        domain_lower = domain.lower()
        res.mx_is_mail_prefix = any(
            h.lower() == f"mail.{domain_lower}" for _, h in mx_records
        )
    
    # BIMI
    res.bimi_exists, res.bimi_record = get_bimi(domain)
    
    # MTA-STS
    res.mta_sts_exists, res.mta_sts_record = get_mta_sts(domain)
    
    # Blacklists (v6.2: now tracks inconclusive checks)
    bl_hits, bl_count, bl_inconclusive = check_domain_blacklists(domain, config['domain_blacklists'])
    res.domain_blacklists_hit = ";".join(bl_hits)
    res.domain_blacklist_count = bl_count
    res.domain_blacklist_inconclusive = bl_inconclusive
    
    ip_bl_hits, ip_bl_count, ip_bl_inconclusive = check_ip_blacklists(res.ip_address, config['ip_blacklists'])
    res.ip_blacklists_hit = ";".join(ip_bl_hits)
    res.ip_blacklist_count = ip_bl_count
    res.ip_blacklist_inconclusive = ip_bl_inconclusive
    
    # Hosting Provider Detection
    ns_records = dns_query(domain, 'NS')
    hosting_result = check_hosting_provider(
        domain, res.ip_address, 
        ns_records=ns_records, 
        ptr_record=res.ptr_record,
        hosting_config=config
    )
    res.hosting_provider = hosting_result["provider"]
    res.hosting_provider_type = hosting_result["provider_type"]
    res.hosting_detected_via = hosting_result["detected_via"]
    res.hosting_asn = hosting_result["asn"]
    res.hosting_asn_org = hosting_result["asn_org"]
    
    # TLS — v4.4: now captures handshake_failed and connection_failed separately
    tls = check_tls(domain, timeout)
    res.https_valid = tls["ok"]
    res.tls_error = tls["error"]
    res.tls_handshake_failed = tls["handshake_failed"]       # v4.4
    res.tls_connection_failed = tls["connection_failed"]     # v4.4
    res.cert_self_signed = tls["self_signed"]
    res.cert_expired = tls["expired"]
    res.cert_wrong_host = tls["wrong_host"]
    
    # HTTP check
    if REQUESTS_AVAILABLE:
        try:
            r = requests.head(f"http://{domain}", timeout=timeout, allow_redirects=False, verify=False)
            res.http_reachable = r.status_code in [200, 301, 302, 307, 308]
            res.http_status = r.status_code
        except:
            pass
    
    # HTTPS with redirects + content
    https_result = follow_redirects(f"https://{domain}", timeout, fetch_content=True)
    res.https_reachable = https_result["ok"]
    res.https_status = https_result["initial_status"]
    res.redirect_count = https_result["hops"]
    res.redirect_chain = "→".join(str(s) for s in https_result["chain"])
    res.redirect_domains = "→".join(https_result["domains"])
    res.redirect_cross_domain = https_result["cross_domain"]
    res.redirect_uses_temp = https_result["uses_temp"]
    res.final_url = https_result["final_url"]
    res.content_length = https_result["content_length"]
    
    all_statuses = https_result["all_statuses"]
    res.status_codes_seen = ";".join(str(s) for s in sorted(all_statuses) if s > 0)
    res.has_401 = 401 in all_statuses
    res.has_403 = 403 in all_statuses
    res.has_429 = 429 in all_statuses
    res.has_503 = 503 in all_statuses
    res.has_5xx = bool(all_statuses & {500, 502, 504})
    
    # Access restriction detection - 401/403 on what should be a public site is suspicious
    if res.has_401 or res.has_403:
        res.is_access_restricted = True
        if res.has_401 and res.has_403:
            res.access_restriction_note = "Both 401 Unauthorized and 403 Forbidden responses"
        elif res.has_401:
            res.access_restriction_note = "401 Unauthorized - requires authentication for public site"
        else:
            res.access_restriction_note = "403 Forbidden - access blocked"
    
    # Content analysis
    content = https_result["content"]
    if not content and res.http_reachable:
        http_result = follow_redirects(f"http://{domain}", timeout, fetch_content=True)
        content = http_result["content"]
        res.content_length = http_result["content_length"]
    
    # === EMPTY PAGE DETECTION ===
    # A reachable domain that returns empty/near-empty content is suspicious
    # (parked, abandoned, or stripped after compromise)
    # But 403/5xx responses aren't "empty" — they're blocked/broken, different signal
    if res.https_reachable or res.http_reachable:
        if not (res.is_access_restricted or res.has_5xx or res.has_503):
            if not content or len(content.strip()) < 50:
                res.is_empty_page = True
    
    if content:
        res.content_hash = hashlib.md5(content).hexdigest()[:12]
        ca = analyze_content(content, res.final_url, domain)
        res.is_minimal_shell = ca["minimal_shell"]
        res.has_js_redirect = ca["js_redirect"]
        res.has_meta_refresh = ca["meta_refresh"]
        res.has_external_js = ca["external_js"]
        res.has_obfuscation = ca["obfuscation"]
        res.has_credential_form = ca["credential_form"]
        res.has_sensitive_fields = ca["sensitive_fields"]
        res.brands_detected = ";".join(ca["brands"])
        res.form_posts_external = ca["form_external"]
        res.malware_links_found = ";".join(ca["malware"])
        res.has_suspicious_iframe = ca["suspicious_iframe"]
        res.is_parking_page = ca["parking"]
        res.phishing_paths_found = ";".join(ca["phishing_paths"])
    
    # Check for hijacked domain / stepping stone indicators
    redirect_chain_urls = res.redirect_chain.split(' → ') if res.redirect_chain else []
    hijack = check_hijacked_domain_indicators(content, res.final_url, redirect_chain_urls)
    res.has_hijack_path_pattern = hijack["has_hijack_path"]
    res.hijack_path_found = hijack["hijack_path"]
    res.has_doc_sharing_lure = hijack["has_doc_lure"]
    res.doc_lure_found = hijack["doc_lure"]
    res.has_phishing_js_behavior = hijack["has_phishing_js"]
    res.phishing_js_patterns = ";".join(hijack["phishing_js_found"])
    res.redirects_to_phishing_infra = hijack["redirects_to_phishing_infra"]
    res.phishing_infra_domain = hijack["phishing_infra"]
    res.has_email_in_url = hijack["has_email_in_url"]
    res.url_email_tracking = hijack["email_tracking"]
    
    # E-commerce / retail scam detection
    if content:
        ecom = analyze_ecommerce_indicators(content, domain)
        res.is_ecommerce_site = ecom["is_ecommerce"]
        res.has_cross_domain_brand_link = len(ecom["cross_domain_brand_links"]) > 0
        res.cross_domain_brand_links = ";".join(ecom["cross_domain_brand_links"])
        
        # Check business identity - especially important for e-commerce
        if ecom["is_ecommerce"]:
            res.missing_business_identity = not ecom["has_business_identity"]
            found_signals = ecom["business_identity_signals"]
            missing_signals = ecom["missing_identity_signals"]
            res.business_identity_signals = f"found:{';'.join(found_signals)}|missing:{';'.join(missing_signals)}"
    
    # Corporate trust signal check - only if we got a 401/403 or couldn't reach the site
    # A domain that blocks access AND has no trust pages is highly suspicious
    if res.is_access_restricted or res.is_minimal_shell or not res.https_reachable:
        trust_signals = check_corporate_trust_signals(domain, timeout=3.0)
        res.trust_pages_checked = ";".join(trust_signals["pages_checked"])
        res.trust_pages_found = ";".join(trust_signals["pages_found"])
        res.missing_trust_signals = trust_signals["missing_trust_signals"]
        
        # If access is restricted AND no trust signals found, mark as opaque entity
        if res.is_access_restricted and res.missing_trust_signals:
            res.is_opaque_entity = True
    
    # App Store Presence Detection (legitimacy signal)
    if APP_STORE_DETECTION_AVAILABLE:
        try:
            app_result = check_app_store_presence(domain, content=content, timeout=5.0)
            res.app_store_has_presence = app_result.get("has_any_app_presence", False)
            res.app_store_confidence = app_result.get("confidence", "none")
            res.app_store_ios_verified = app_result.get("ios_aasa", {}).get("exists", False)
            res.app_store_android_verified = app_result.get("android_asset_links", {}).get("exists", False)
            res.app_store_page_links = app_result.get("has_app_store_links", False)
            res.app_store_itunes_match = app_result.get("has_itunes_match", False)
            res.app_store_ios_app_ids = app_result.get("app_store_ios_app_ids", "")
            res.app_store_android_packages = app_result.get("app_store_android_packages", "")
            res.app_store_methods_found = app_result.get("app_store_methods_found", "")
            res.app_store_summary = " | ".join(app_result.get("summary_lines", []))
        except Exception:
            pass  # Non-critical — don't break analysis if app store check fails
    
    # TLD Variant Spoofing Detection
    # Check if signup domain is a TLD variant of an established business
    # e.g., gordondown.uk spoofing gordondown.co.uk
    try:
        tld_variant = check_tld_variant_spoofing(domain, signup_content=content, timeout=timeout)
        res.tld_variant_detected = tld_variant["tld_variant_detected"]
        res.tld_variant_domain = tld_variant["variant_domain"]
        res.tld_variant_has_content = tld_variant["variant_has_content"]
        res.tld_variant_has_email_infra = tld_variant["variant_has_email_infra"]
        res.tld_variant_domain_age_days = tld_variant["variant_domain_age_days"]
        res.tld_variant_content_words = tld_variant["variant_content_words"]
        res.tld_variant_signup_content_words = tld_variant["signup_content_words"]
        res.tld_variant_summary = tld_variant["summary"]
        
        # TLD variant allowlist: suppress for domains explicitly cleared by admin review
        tld_variant_allowlist = [d.lower().strip() for d in config.get('tld_variant_allowlist', [])]
        if res.tld_variant_detected:
            if domain_lower in tld_variant_allowlist or any(domain_lower.endswith('.' + a) for a in tld_variant_allowlist):
                res.tld_variant_detected = False
                res.tld_variant_summary = f"ALLOWLISTED — {res.tld_variant_domain} variant suppressed by admin"
    except Exception as e:
        # Surface error in results so it's visible during debugging
        res.tld_variant_summary = f"CHECK ERROR: {type(e).__name__}: {str(e)[:200]}"
    
    # === VIRUSTOTAL REPUTATION CHECK ===
    # Uses the VT API to check domain reputation across 70+ security vendors
    vt_api_key = src.get('vt_api_key', '') or os.environ.get('VT_API_KEY', '')
    if VT_CHECKER_AVAILABLE and vt_api_key:
        try:
            vt = VirusTotalChecker(api_key=vt_api_key)
            vt_result = vt.check_domain(domain)
            res.vt_available = vt_result.get("vt_available", False)
            res.vt_malicious_count = vt_result.get("malicious_count", 0)
            res.vt_suspicious_count = vt_result.get("suspicious_count", 0)
            res.vt_total_vendors = vt_result.get("total_vendors", 0)
            res.vt_detection_rate = vt_result.get("detection_rate", 0.0)
            res.vt_community_score = vt_result.get("community_score", 0)
            res.vt_reputation = vt_result.get("reputation", 0)
            res.vt_threat_names = ";".join(vt_result.get("threat_names", []))
            res.vt_malicious_vendors = ";".join(vt_result.get("malicious_vendors", []))
            res.vt_categories = json.dumps(vt_result.get("categories", {}))
            res.vt_last_analysis = vt_result.get("last_analysis_date", "") or ""
        except Exception:
            pass  # Non-critical — don't break analysis if VT check fails
    
    # === HACKLINK / SEO SPAM DETECTION ===
    # Scans page content for Turkish hacklink injection, gambling keywords, 
    # WordPress compromise indicators, and hidden SEO spam
    if HACKLINK_SCANNER_AVAILABLE:
        try:
            hl_scanner = HacklinkKeywordScanner(timeout=int(timeout))
            # Pass pre-fetched content to avoid double-fetching
            content_str = content.decode('utf-8', errors='replace') if isinstance(content, bytes) else content
            hl_result = hl_scanner.scan(domain, content=content_str)
            res.hacklink_detected = hl_result.get("hacklink_detected", False)
            res.hacklink_score = hl_result.get("score", 0)
            res.hacklink_keywords = ";".join(hl_result.get("keywords_found", []))
            res.hacklink_injection_patterns = ";".join(hl_result.get("injection_patterns", []))
            res.hacklink_is_wordpress = hl_result.get("is_wordpress", False)
            res.hacklink_wp_compromised = hl_result.get("wp_compromised", False)
            vuln_plugins = hl_result.get("vulnerable_plugins", [])
            if vuln_plugins:
                res.hacklink_vulnerable_plugins = ";".join(
                    f"{p.get('plugin','')}({p.get('risk','')})" if isinstance(p, dict) else str(p)
                    for p in vuln_plugins
                )
            res.hacklink_spam_link_count = hl_result.get("spam_link_count", 0)
            
            # === Extract sub-signals for individual scoring ===
            res.hacklink_is_cpanel = hl_result.get("is_cpanel", False)
            
            # Parse injection_patterns for malicious_script and hidden_injection flags
            inj_patterns = hl_result.get("injection_patterns", [])
            # v7.2: Use multi-signal confidence instead of binary pattern matching
            ms_confidence = hl_result.get("malicious_script_confidence", "NONE")
            res.hacklink_malicious_script = ms_confidence in ("HIGH", "MEDIUM")
            res.hacklink_malicious_script_confidence = ms_confidence
            ms_signals = hl_result.get("malicious_script_signals", [])
            res.hacklink_malicious_script_signals = ";".join(ms_signals) if ms_signals else ""
            res.hacklink_malicious_script_score = hl_result.get("malicious_script_score", 0)
            res.hacklink_hidden_injection = any("hidden_content" in p for p in inj_patterns)
            
            # Suspicious external scripts
            sus_scripts = hl_result.get("suspicious_scripts", [])
            if sus_scripts:
                res.hacklink_suspicious_scripts = ";".join(sus_scripts[:10])
        except Exception:
            pass  # Non-critical — don't break analysis if hacklink check fails
    
    # RDAP
    if check_rdap:
        res.rdap_created, res.domain_age_days = rdap_lookup(domain, timeout)
        if res.domain_age_days >= 0:
            res.domain_age_source = "rdap"
    
    # WHOIS fallback if RDAP returned no creation date
    if check_rdap and res.domain_age_days < 0:
        res.whois_created, res.domain_age_days = whois_lookup(domain)
        if res.domain_age_days >= 0:
            res.domain_age_source = "whois"
    
    # === WHOIS ENRICHMENT (transfer lock, registrar, update recency) ===
    if check_rdap:
        try:
            we = whois_enrich(domain)
            res.whois_registrar = we["registrar"]
            res.whois_statuses = ";".join(we["statuses"])
            res.whois_updated = we["updated_date"]
            res.whois_recently_updated_days = we["updated_days_ago"]
            res.domain_transfer_locked = we["transfer_locked"]
            # Recently-added lock on established domain = post-compromise lockdown signal
            # Lock present + WHOIS updated ≤90 days + domain >1yr old
            if (we["transfer_locked"] and 
                we["updated_days_ago"] >= 0 and we["updated_days_ago"] <= 90 and
                res.domain_age_days >= 365):
                res.domain_transfer_lock_recent = True
            if (we["updated_days_ago"] >= 0 and we["updated_days_ago"] <= 30
                    and res.domain_age_days >= 365):
                res.whois_recently_updated = True
        except Exception:
            pass
    
    # === CERTIFICATE TRANSPARENCY LOG CHECK ===
    try:
        ct = check_cert_transparency(domain, timeout=min(timeout, 8.0))
        res.ct_log_count = ct["ct_count"]
        res.ct_recent_issuance = ct["recent_issuance"]
        res.ct_issuers = ";".join(ct["issuers"])
        res.ct_first_seen = ct["first_seen"]
        res.ct_last_seen = ct["last_seen"]
    except Exception:
        pass
    
    # Score
    calculate_score(res, config)
    
    return asdict(res)
