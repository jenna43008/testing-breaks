"""
Domain Analysis Engine for Sender Approval
==========================================
Core analysis logic extracted for use in web app.
"""

from __future__ import annotations

import re
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

from config import DEFAULT_CONFIG, get_weight, get_combo_weight


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
    
    # === EMAIL: BIMI ===
    bimi_exists: bool = False
    bimi_record: str = ""
    
    # === EMAIL: MTA-STS ===
    mta_sts_exists: bool = False
    mta_sts_record: str = ""
    
    # === BLACKLISTS ===
    domain_blacklists_hit: str = ""
    domain_blacklist_count: int = 0
    ip_blacklists_hit: str = ""
    ip_blacklist_count: int = 0
    
    # === DOMAIN INFO ===
    rdap_created: str = ""
    domain_age_days: int = -1
    is_suspicious_tld: bool = False
    is_free_email_domain: bool = False
    is_free_hosting: bool = False
    is_url_shortener: bool = False
    is_disposable_email: bool = False
    typosquat_target: str = ""
    typosquat_similarity: float = 0.0
    
    # === WEB: TLS/CERT ===
    https_valid: bool = False
    tls_error: str = ""
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
    
    # === SCORING DETAILS ===
    signals_triggered: str = ""
    combos_triggered: str = ""


# ============================================================================
# CONSTANTS
# ============================================================================

DNS_TIMEOUT = 5.0
WEB_TIMEOUT = 8.0
MAX_REDIRECTS = 10

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

BRAND_KEYWORDS = [
    b'paypal', b'amazon', b'microsoft', b'apple', b'google', b'facebook',
    b'instagram', b'netflix', b'bank of america', b'chase', b'wells fargo',
    b'usps', b'fedex', b'ups', b'dhl', b'irs', b'dropbox', b'docusign',
]

CREDENTIAL_PATTERNS = [b'type="password"', b"type='password'", b'name="password"']
SENSITIVE_PATTERNS = [b'name="ssn"', b'name="card_number"', b'name="cvv"']
JS_REDIRECT_PATTERNS = [b'location.href', b'location.replace', b'window.location']
MALWARE_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.msi', '.jar', '.vbs', '.apk']


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


def check_blacklist(query: str, zone: str) -> bool:
    if not DNS_AVAILABLE:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        resolver.resolve(f"{query}.{zone}", 'A')
        return True
    except Exception:
        return False


def check_domain_blacklists(domain: str, blacklists: List[str]) -> Tuple[List[str], int]:
    hits = [bl for bl in blacklists if check_blacklist(domain, bl)]
    return hits, len(hits)


def check_ip_blacklists(ip: str, blacklists: List[str]) -> Tuple[List[str], int]:
    if not ip:
        return [], 0
    reversed_ip = '.'.join(reversed(ip.split('.')))
    hits = [bl for bl in blacklists if check_blacklist(reversed_ip, bl)]
    return hits, len(hits)


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


# ============================================================================
# WEB FUNCTIONS
# ============================================================================

def check_tls(domain: str, timeout: float) -> Dict:
    result = {"ok": False, "error": "", "self_signed": False, "expired": False, "wrong_host": False}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                result["ok"] = True
    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        result["error"] = str(e)[:150]
        result["self_signed"] = "self signed" in err or "self-signed" in err
        result["expired"] = "expired" in err
        result["wrong_host"] = "hostname" in err or "match" in err
    except Exception as e:
        result["error"] = str(e)[:150]
    return result


def follow_redirects(url: str, timeout: float, fetch_content: bool = False) -> Dict:
    if not REQUESTS_AVAILABLE:
        return {"ok": False, "initial_status": 0, "hops": 0, "chain": [], "domains": [], 
                "cross_domain": False, "uses_temp": False, "final_url": url, 
                "all_statuses": set(), "content": b"", "content_length": -1}
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
    
    result = {
        "ok": False, "initial_status": 0, "hops": 0,
        "chain": [], "domains": [], "cross_domain": False,
        "uses_temp": False, "final_url": url, "all_statuses": set(),
        "content": b"", "content_length": -1,
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
            method = "GET" if (fetch_content and i == MAX_REDIRECTS) else "HEAD"
            resp = session.request(method, current, allow_redirects=False, timeout=timeout, verify=True, stream=True)
            status = resp.status_code
            
            if status in (405, 501) and method == "HEAD":
                resp = session.get(current, allow_redirects=False, timeout=timeout, verify=True, stream=True)
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
            
            if fetch_content and status == 200:
                try:
                    result["content"] = resp.content[:50000]
                    result["content_length"] = len(result["content"])
                except:
                    pass
            return result
        except:
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
    for brand in BRAND_KEYWORDS:
        brand_str = brand.decode('utf-8', errors='ignore').replace(' ', '')
        if brand in content_lower and brand_str not in final_domain and brand_str not in domain:
            result["brands"].append(brand.decode('utf-8', errors='ignore'))
    result["brands"] = result["brands"][:5]
    
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


# ============================================================================
# SCORING & SUMMARY
# ============================================================================

def generate_summary(res: DomainApprovalResult, signals: Set[str], rdap_enabled: bool) -> str:
    """Generate comprehensive summary showing ALL triggered signals and their email impacts."""
    
    all_issues = []  # Format: "ISSUE → IMPACT"
    positives = []
    
    # === CRITICAL ISSUES ===
    if res.domain_blacklist_count > 0:
        all_issues.append(f"BLACKLISTED DOMAIN ({res.domain_blacklist_count} lists) → Emails BLOCKED by Gmail/Outlook/Yahoo")
    
    if res.ip_blacklist_count > 0:
        all_issues.append(f"BLACKLISTED IP ({res.ip_blacklist_count} lists) → Emails BLOCKED by major providers")
    
    if res.spf_mechanism == "+all":
        all_issues.append("SPF +all → Domain SPOOFABLE; anyone can forge emails as this sender")
    
    if rdap_enabled and res.domain_age_days >= 0 and res.domain_age_days < 7:
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
    
    if res.brands_detected:
        all_issues.append(f"BRAND IMPERSONATION ({res.brands_detected}) → Triggers phishing filters")
    
    if res.malware_links_found:
        all_issues.append("MALWARE LINKS DETECTED → Domain will be blacklisted across providers")
    
    if res.has_credential_form and res.brands_detected:
        all_issues.append("CREDENTIAL FORM + BRAND IMPERSONATION → Classic phishing; will be blocked")
    
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
    
    if not res.ptr_exists:
        all_issues.append("NO PTR RECORD → Corporate/enterprise email filters may reject")
    elif not res.ptr_matches_forward:
        all_issues.append("PTR MISMATCH → Forward/reverse DNS inconsistent; triggers spam filters")
    
    if not res.https_valid:
        all_issues.append("NO VALID HTTPS → May indicate abandoned or suspicious domain")
    
    if res.is_suspicious_tld:
        all_issues.append("HIGH-ABUSE TLD → This domain extension faces extra spam scrutiny")
    
    if res.is_free_hosting:
        all_issues.append("FREE HOSTING PROVIDER → Associated with spam; limited reputation potential")
    
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
    
    if res.has_credential_form and not res.brands_detected:
        all_issues.append("CREDENTIAL FORM DETECTED → Login form on landing page")
    
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
    
    if res.mx_exists and not res.mx_is_null:
        positives.append("MX configured")
    
    if res.ptr_exists and res.ptr_matches_forward:
        positives.append("PTR matches")
    
    # === BUILD SUMMARY ===
    parts = []
    
    # Recommendation with score
    if res.recommendation == "DENY":
        parts.append(f"⛔ DENY (Score: {res.risk_score}/100, Threshold: 50)")
    else:
        parts.append(f"✅ APPROVE (Score: {res.risk_score}/100)")
    
    # ALL issues with impacts
    if all_issues:
        parts.append("ISSUES FOUND: " + " • ".join(all_issues))
    else:
        parts.append("ISSUES FOUND: None")
    
    # Positive signals
    if positives:
        parts.append("POSITIVE SIGNALS: " + ", ".join(positives))
    
    # Redirect path if applicable
    if res.redirect_count > 0 and res.redirect_domains:
        parts.append(f"REDIRECT PATH: {res.redirect_domains}")
    
    return " | ".join(parts)


def calculate_score(res: DomainApprovalResult, config: dict) -> None:
    score = 0
    signals: Set[str] = set()
    weights = config.get('weights', DEFAULT_CONFIG['weights'])
    threshold = config.get('approve_threshold', 50)
    
    # Email Auth - these are DELIVERABILITY concerns only, NOT fraud signals
    # A domain missing these should get warnings, not denial
    if not res.spf_exists:
        score += weights.get('no_spf', 8)
        signals.add("no_spf")
    else:
        if res.spf_mechanism == "+all":
            score += weights.get('spf_pass_all', 40)  # This IS a security issue - allows spoofing
            signals.add("spf_pass_all")
        elif res.spf_mechanism == "?all":
            score += weights.get('spf_neutral_all', 5)
            signals.add("spf_neutral_all")
        elif res.spf_mechanism == "~all":
            score += weights.get('spf_softfail_all', 2)  # Very minor - this is common and acceptable
            signals.add("spf_softfail_all")
    
    if not res.dkim_exists:
        score += weights.get('no_dkim', 6)
        signals.add("no_dkim")
    
    if not res.dmarc_exists:
        score += weights.get('no_dmarc', 10)
        signals.add("no_dmarc")
    else:
        if res.dmarc_policy == "none":
            score += weights.get('dmarc_p_none', 5)
            signals.add("dmarc_p_none")
        if not res.dmarc_rua:
            score += weights.get('dmarc_no_rua', 2)
            signals.add("dmarc_no_rua")
    
    if not res.mx_exists:
        score += weights.get('no_mx', 8)
        signals.add("no_mx")
    elif res.mx_is_null:
        score += weights.get('null_mx', 12)
        signals.add("null_mx")
    
    if not res.ptr_exists:
        score += weights.get('no_ptr', 4)
        signals.add("no_ptr")
    elif not res.ptr_matches_forward:
        score += weights.get('ptr_mismatch', 5)
        signals.add("ptr_mismatch")
    
    if res.bimi_exists:
        score += weights.get('has_bimi', -8)
        signals.add("has_bimi")
    if res.mta_sts_exists:
        score += weights.get('has_mta_sts', -5)
        signals.add("has_mta_sts")
    
    # Blacklists - HIGH weight, these are real fraud signals
    if res.domain_blacklist_count > 0:
        score += weights.get('domain_blacklisted', 40) * min(res.domain_blacklist_count, 3)
        signals.add("domain_blacklisted")
    if res.ip_blacklist_count > 0:
        score += weights.get('ip_blacklisted', 35) * min(res.ip_blacklist_count, 3)
        signals.add("ip_blacklisted")
    
    # Domain age
    if res.domain_age_days >= 0:
        if res.domain_age_days < 7:
            score += weights.get('domain_lt_7d', 35)
            signals.add("domain_lt_7d")
        if res.domain_age_days < 30:
            score += weights.get('domain_lt_30d', 12)
            signals.add("domain_lt_30d")
        elif res.domain_age_days < 90:
            score += weights.get('domain_lt_90d', 5)
            signals.add("domain_lt_90d")
    
    # Domain type
    if res.is_suspicious_tld:
        score += weights.get('suspicious_tld', 12)
        signals.add("suspicious_tld")
    if res.is_free_email_domain:
        score += weights.get('free_email_domain', 20)
        signals.add("free_email_domain")
    if res.is_disposable_email:
        score += weights.get('disposable_email', 30)
        signals.add("disposable_email")
    if res.typosquat_target:
        score += weights.get('typosquat_detected', 25)
        signals.add("typosquat_detected")
    if res.is_free_hosting:
        score += weights.get('free_hosting', 12)
        signals.add("free_hosting")
    
    # Web/TLS
    if not res.https_valid:
        score += weights.get('no_https', 25)
        signals.add("no_https")
    if res.cert_expired:
        score += weights.get('cert_expired', 15)
        signals.add("cert_expired")
    if res.cert_self_signed:
        score += weights.get('cert_self_signed', 12)
        signals.add("cert_self_signed")
    
    # Redirects
    if res.redirect_count >= 2:
        score += weights.get('redirect_chain_2plus', 12)
        signals.add("redirect_chain_2plus")
    if res.redirect_cross_domain:
        score += weights.get('redirect_cross_domain', 12)
        signals.add("redirect_cross_domain")
    if res.redirect_uses_temp:
        score += weights.get('redirect_temp_302_307', 10)
        signals.add("redirect_temp_302_307")
    
    # Content
    if res.is_minimal_shell:
        score += weights.get('minimal_shell', 15)
        signals.add("minimal_shell")
    if res.has_js_redirect:
        score += weights.get('js_redirect', 12)
        signals.add("js_redirect")
    if res.has_credential_form:
        score += weights.get('credential_form', 20)
        signals.add("credential_form")
    if res.brands_detected:
        score += weights.get('brand_impersonation', 22)
        signals.add("brand_impersonation")
    if res.phishing_paths_found:
        score += weights.get('phishing_paths', 20)
        signals.add("phishing_paths")
    if res.malware_links_found:
        score += weights.get('malware_links', 25)
        signals.add("malware_links")
    
    # Combos
    combos = config.get('combos', DEFAULT_CONFIG['combos'])
    combos_hit = []
    for combo_key, bonus in combos.items():
        parts = combo_key.split('+')
        if len(parts) == 2 and parts[0] in signals and parts[1] in signals:
            score += bonus
            combos_hit.append(combo_key)
    
    res.risk_score = max(0, min(score, 100))
    
    bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
    res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
    
    res.recommendation = "APPROVE" if res.risk_score <= threshold else "DENY"
    res.signals_triggered = ";".join(sorted(signals))
    res.combos_triggered = ";".join(combos_hit)
    res.summary = generate_summary(res, signals, res.domain_age_days >= 0)


# ============================================================================
# MAIN ANALYSIS FUNCTION
# ============================================================================

def analyze_domain(domain: str, timeout: float = 10.0, check_rdap: bool = True,
                   weights: dict = None, threshold: int = 50) -> dict:
    """
    Main entry point for domain analysis.
    Returns dict with all results.
    """
    config = {
        'weights': weights or DEFAULT_CONFIG['weights'],
        'approve_threshold': threshold,
        'suspicious_tlds': DEFAULT_CONFIG.get('suspicious_tlds', []),
        'protected_brands': DEFAULT_CONFIG.get('protected_brands', []),
        'disposable_domains': DEFAULT_CONFIG.get('disposable_domains', []),
        'domain_blacklists': DEFAULT_CONFIG.get('domain_blacklists', []),
        'ip_blacklists': DEFAULT_CONFIG.get('ip_blacklists', []),
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
    res.is_free_email_domain = domain_lower in FREE_EMAIL_PROVIDERS
    res.is_free_hosting = any(p in domain_lower for p in FREE_HOSTING_PATTERNS)
    res.is_url_shortener = domain_lower in URL_SHORTENERS
    res.is_disposable_email = is_disposable_email(domain_lower, config['disposable_domains'])
    res.typosquat_target, res.typosquat_similarity = check_typosquatting(domain, config['protected_brands'])
    
    # SPF
    spf_record, spf_exists, spf_parsed = get_spf(domain)
    res.spf_record = spf_record[:500]
    res.spf_exists = spf_exists
    if spf_exists:
        res.spf_mechanism = spf_parsed.get("mechanism", "")
        res.spf_includes = ";".join(spf_parsed.get("includes", []))
        res.spf_lookup_count = spf_parsed.get("lookups", 0)
        res.spf_syntax_valid = spf_parsed.get("valid", True)
    
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
    
    # BIMI
    res.bimi_exists, res.bimi_record = get_bimi(domain)
    
    # MTA-STS
    res.mta_sts_exists, res.mta_sts_record = get_mta_sts(domain)
    
    # Blacklists
    bl_hits, bl_count = check_domain_blacklists(domain, config['domain_blacklists'])
    res.domain_blacklists_hit = ";".join(bl_hits)
    res.domain_blacklist_count = bl_count
    
    ip_bl_hits, ip_bl_count = check_ip_blacklists(res.ip_address, config['ip_blacklists'])
    res.ip_blacklists_hit = ";".join(ip_bl_hits)
    res.ip_blacklist_count = ip_bl_count
    
    # TLS
    tls = check_tls(domain, timeout)
    res.https_valid = tls["ok"]
    res.tls_error = tls["error"]
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
    res.has_403 = 403 in all_statuses
    res.has_429 = 429 in all_statuses
    res.has_503 = 503 in all_statuses
    res.has_5xx = bool(all_statuses & {500, 502, 504})
    
    # Content analysis
    content = https_result["content"]
    if not content and res.http_reachable:
        http_result = follow_redirects(f"http://{domain}", timeout, fetch_content=True)
        content = http_result["content"]
        res.content_length = http_result["content_length"]
    
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
    
    # RDAP
    if check_rdap:
        res.rdap_created, res.domain_age_days = rdap_lookup(domain, timeout)
    
    # Score
    calculate_score(res, config)
    
    return asdict(res)
