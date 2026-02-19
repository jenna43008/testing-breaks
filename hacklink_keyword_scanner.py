"""
Hacklink Keyword Scanner
========================
Scans domain page content for hacklink SEO poisoning indicators.

Hacklink campaigns (predominantly Turkish-origin) inject hidden keywords and links
into compromised websites. These include gambling, pharmaceutical, and adult content
keywords designed to boost attacker-controlled sites in search rankings.

IMPORTANT: HTTP errors (403, timeout, SSL failures) are treated as risk signals,
not benign outcomes. A legitimate business domain that blocks access, times out,
or has certificate issues is itself suspicious for a sending domain.
"""

import re
import socket
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Optional


# ================================================================
# Hacklink Keyword Families
# ================================================================

TURKISH_HACKLINK_KEYWORDS = [
    "hacklink", "hack link", "hacklink satın al", "hacklink al",
    "hacklink panel", "hacklink servisi", "hacklink fiyat",
    "bahis", "bahis siteleri", "canlı bahis", "illegal bahis",
    "casino", "canlı casino", "online casino", "casino siteleri",
    "kumar", "kumar siteleri", "slot", "slot oyunları",
    "bet", "betting", "betist", "betpark", "bahsegel",
    "rulet", "poker", "blackjack", "bakara",
    "deneme bonusu", "bonus veren siteler", "free bonus",
    "kaçak iddaa", "iddaa", "spor bahis",
    "escort", "escort bayan",
    "porno", "sex", "xxx",
    "cialis", "viagra", "hap",
    "oto çekici", "nakliyat",
]

SOCGHOLISH_PATTERNS = [
    r'<script[^>]*src=["\']https?://[^"\']*\.js["\'][^>]*>.*?</script>',
    r'document\.write\s*\(\s*unescape\s*\(',
    r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)',
    r'String\.fromCharCode\s*\(\s*\d+',
    r'window\[.atob\(',
    r'<script[^>]*>\s*var\s+_0x[a-f0-9]+\s*=',
]

HIDDEN_CONTENT_PATTERNS = [
    r'display\s*:\s*none[^}]*hacklink',
    r'font-size\s*:\s*[01]px',
    r'position\s*:\s*absolute[^}]*left\s*:\s*-\d{3,}',
    r'text-indent\s*:\s*-\d{3,}',
    r'overflow\s*:\s*hidden[^}]*height\s*:\s*[01]px',
    r'visibility\s*:\s*hidden[^}]*<a\s+href',
    r'opacity\s*:\s*0[^}]*<a\s+href',
    r'z-index\s*:\s*-\d+[^}]*<a\s+href',
]

SUSPICIOUS_SCRIPT_DOMAINS = [
    r'cdn\.jsdelivr\.net/npm/.*(?:analytics|tracker|pixel)',
    r'statcounter\.com',
    r'\.top/.*\.js',
    r'\.buzz/.*\.js',
    r'\.click/.*\.js',
    r'\.link/.*\.js',
    r'googletagmanager.*(?!google)',
    r'google-analytics.*\.(?!google\.com)',
]

WP_COMPROMISE_PATTERNS = [
    r'wp-content/plugins/[^/]+/[^"\']+\.js\?ver=\d+\.\d+\.\d+.*(?:eval|document\.write)',
    r'wp-includes/.*(?:eval|base64_decode)',
    r'/wp-admin/admin-ajax\.php.*action=(?!heartbeat)',
]


class HacklinkKeywordScanner:
    """Scans domains for hacklink SEO poisoning indicators."""

    def __init__(self, timeout: int = 10, max_content_size: int = 500_000):
        self.timeout = timeout
        self.max_content_size = max_content_size

    def scan(self, domain: str, content: Optional[str] = None) -> Dict:
        """
        Scan a domain for hacklink injection indicators.

        Args:
            domain: Domain name to scan
            content: Optional pre-fetched page content. If provided, skips
                     HTTP fetch (useful when caller already has the content).

        Returns:
            Dict with hacklink_detected, score (0-30), keywords, findings
        """
        findings = []
        keywords_found = []
        injection_patterns = []
        score = 0
        page_content = content  # Use pre-fetched content if provided
        fetch_status = 200 if content else None
        fetch_error = None
        fetch_error_type = None

        # Attempt to fetch page content (only if not pre-fetched)
        if page_content is None:
            for protocol in ["https", "http"]:
                url = f"{protocol}://{domain}"
                try:
                    page_content, fetch_status = self._fetch_content(url)
                    if page_content:
                        break
                except urllib.error.HTTPError as e:
                    fetch_status = e.code
                    fetch_error = f"HTTP {e.code} {e.reason}"
                    fetch_error_type = "http_error"
                    continue
                except urllib.error.URLError as e:
                    reason = str(e.reason)
                    fetch_error = f"Connection failed: {reason}"
                    if "timed out" in reason.lower() or "timeout" in reason.lower():
                        fetch_error_type = "timeout"
                    elif "ssl" in reason.lower() or "certificate" in reason.lower():
                        fetch_error_type = "ssl_error"
                    elif "refused" in reason.lower():
                        fetch_error_type = "connection_refused"
                    elif "name or service not known" in reason.lower() or "getaddrinfo" in reason.lower():
                        fetch_error_type = "dns_failure"
                    else:
                        fetch_error_type = "connection_error"
                    continue
                except socket.timeout:
                    fetch_error = "Connection timed out"
                    fetch_error_type = "timeout"
                    continue
                except Exception as e:
                    fetch_error = str(e)[:200]
                    fetch_error_type = "unknown"
                    continue

        # ================================================================
        # SCORE HTTP ERRORS AS RISK SIGNALS
        # A legitimate sending domain that can't serve a web page is suspicious
        # ================================================================
        if not page_content:
            score, findings = self._score_fetch_failure(
                domain, fetch_status, fetch_error, fetch_error_type, score, findings
            )

            # Even without page content, check if domain NAME contains keywords
            domain_name_keywords = self._check_domain_name(domain)
            if domain_name_keywords:
                score += 5
                findings.append({
                    "severity": "high",
                    "category": "domain_name_keywords",
                    "detail": f"Domain name contains hacklink-associated keywords: "
                              f"{', '.join(domain_name_keywords)}. Combined with HTTP "
                              f"errors, this is a strong compromise indicator."
                })

            return {
                "hacklink_detected": len(domain_name_keywords) >= 1,
                "score": min(score, 30),
                "keywords_found": domain_name_keywords,
                "injection_patterns": [],
                "suspicious_scripts": [],
                "wp_compromised": False,
                "is_wordpress": False,
                "is_cpanel": False,
                "wp_plugins": [],
                "vulnerable_plugins": [],
                "spam_link_count": 0,
                "google_dorks": self._generate_google_dorks(domain, domain_name_keywords, [], False),
                "findings": findings,
                "fetch_error": fetch_error,
                "fetch_error_type": fetch_error_type,
                "fetch_status": fetch_status,
            }

        content_lower = page_content.lower()

        # ----- 0. Domain Name Keyword Check -----
        # Check if the domain name itself contains hacklink keywords
        domain_name_keywords = self._check_domain_name(domain)
        if domain_name_keywords:
            keywords_found.extend(domain_name_keywords)
            score += 5
            findings.append({
                "severity": "high",
                "category": "domain_name_keywords",
                "detail": f"Domain name contains hacklink-associated keywords: "
                          f"{', '.join(domain_name_keywords)}. The domain itself may be "
                          f"part of a hacklink/SEO spam network."
            })

        # ----- 1. Turkish Hacklink Keyword Scan -----
        for keyword in TURKISH_HACKLINK_KEYWORDS:
            if keyword.lower() in content_lower:
                keywords_found.append(keyword)

        if len(keywords_found) >= 5:
            score += 30
            findings.append({
                "severity": "critical",
                "category": "hacklink_keywords",
                "detail": f"CRITICAL: {len(keywords_found)} hacklink keywords found in page source: "
                          f"{', '.join(keywords_found[:10])}{'...' if len(keywords_found) > 10 else ''}"
            })
        elif len(keywords_found) >= 2:
            score += 20
            findings.append({
                "severity": "high",
                "category": "hacklink_keywords",
                "detail": f"Multiple hacklink keywords detected: {', '.join(keywords_found)}"
            })
        elif len(keywords_found) == 1:
            score += 8
            findings.append({
                "severity": "medium",
                "category": "hacklink_keywords",
                "detail": f"Single hacklink keyword detected: {keywords_found[0]}"
            })

        # ----- 2. Hidden Content Injection -----
        for pattern in HIDDEN_CONTENT_PATTERNS:
            matches = re.findall(pattern, page_content, re.IGNORECASE | re.DOTALL)
            if matches:
                injection_patterns.append(f"hidden_content: {pattern[:50]}")
                if score < 25:
                    score += 10
                findings.append({
                    "severity": "critical",
                    "category": "hidden_injection",
                    "detail": f"Hidden content injection detected (CSS hiding technique). "
                              f"Pattern: {pattern[:60]}..."
                })

        # ----- 3. SocGholish/Malicious Script Detection -----
        for pattern in SOCGHOLISH_PATTERNS:
            matches = re.findall(pattern, page_content, re.IGNORECASE | re.DOTALL)
            if matches:
                injection_patterns.append(f"malicious_script: {pattern[:50]}")
                score = min(score + 15, 30)
                findings.append({
                    "severity": "critical",
                    "category": "malicious_script",
                    "detail": f"Potential SocGholish/FakeUpdates script injection detected."
                })
                break

        # ----- 4. Suspicious External Scripts -----
        script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', page_content, re.IGNORECASE)
        suspicious_scripts = []
        for src in script_srcs:
            for pattern in SUSPICIOUS_SCRIPT_DOMAINS:
                if re.search(pattern, src, re.IGNORECASE):
                    suspicious_scripts.append(src)
                    break

        if suspicious_scripts:
            score = min(score + 8, 30)
            findings.append({
                "severity": "high",
                "category": "suspicious_scripts",
                "detail": f"Suspicious external scripts loaded: "
                          f"{', '.join(suspicious_scripts[:5])}"
            })

        # ----- 5. WordPress & cPanel Detection (Common Compromise Targets) -----
        wp_compromised = False
        is_wordpress = bool(re.search(r'wp-content|wp-includes|wordpress', content_lower))
        is_cpanel = bool(re.search(
            r'cpanel|whm\.autopkg|cpsess[a-f0-9]+|/frontend/|webmail\.\w+\.\w+|'
            r'powered\s*by\s*cpanel|cpanel\s*login|2082|2083|2086|2087',
            content_lower
        ))

        for pattern in WP_COMPROMISE_PATTERNS:
            if re.search(pattern, page_content, re.IGNORECASE):
                wp_compromised = True
                injection_patterns.append("wordpress_compromise")
                break

        if wp_compromised:
            score = min(score + 5, 30)
            findings.append({
                "severity": "high",
                "category": "cms_compromise",
                "detail": "WordPress compromise indicators detected. Poorly maintained CMS "
                          "sites are primary targets for hacklink injection campaigns."
            })
        elif is_wordpress:
            score = min(score + 3, 30)
            findings.append({
                "severity": "medium",
                "category": "cms_target",
                "detail": "WordPress CMS detected. WordPress is the #1 target for hacklink "
                          "injection campaigns due to plugin vulnerabilities and weak admin "
                          "credentials. Presence of WordPress elevates compromise risk."
            })

        if is_cpanel:
            score = min(score + 3, 30)
            findings.append({
                "severity": "medium",
                "category": "cpanel_target",
                "detail": "cPanel hosting detected. cPanel shared hosting environments are "
                          "frequently targeted in hacklink campaigns — a single compromised "
                          "account can expose all sites on the server."
            })

        # ----- 5b. WordPress Plugin Vulnerability Audit -----
        wp_plugins = []
        vulnerable_plugins = []
        if is_wordpress:
            wp_plugins = self._extract_wp_plugins(page_content)
            if wp_plugins:
                vulnerable_plugins = self._check_plugin_vulnerabilities(wp_plugins)
                if vulnerable_plugins:
                    vuln_names = [f"{v['plugin']} ({v['risk']})" for v in vulnerable_plugins]
                    score = min(score + 5, 30)
                    findings.append({
                        "severity": "high",
                        "category": "wp_vulnerable_plugins",
                        "detail": f"WordPress plugins with known vulnerabilities detected: "
                                  f"{', '.join(vuln_names[:8])}. These are common exploit paths "
                                  f"for hacklink injection campaigns."
                    })
                elif wp_plugins:
                    findings.append({
                        "severity": "info",
                        "category": "wp_plugins_detected",
                        "detail": f"WordPress plugins detected: {', '.join(wp_plugins[:10])}. "
                                  f"No known high-risk plugins identified."
                    })

        # ----- 6. Meta Tag Anomalies -----
        meta_anomalies = self._check_meta_anomalies(page_content)
        if meta_anomalies:
            score = min(score + 5, 30)
            findings.extend(meta_anomalies)

        # ----- 7. Excessive Outbound Links to Gambling/Pharma -----
        spam_links = self._count_spam_outbound_links(page_content)
        if spam_links > 10:
            score = min(score + 10, 30)
            findings.append({
                "severity": "critical",
                "category": "spam_links",
                "detail": f"{spam_links} outbound links to gambling/pharma/adult domains detected."
            })
        elif spam_links > 3:
            score = min(score + 5, 30)
            findings.append({
                "severity": "high",
                "category": "spam_links",
                "detail": f"{spam_links} suspicious outbound links to known spam categories."
            })

        # ----- 8. Page content anomalies -----
        # Strip HTML tags to measure VISIBLE text (not raw HTML size)
        visible_text = re.sub(r'<[^>]+>', ' ', page_content)
        visible_text = re.sub(r'\s+', ' ', visible_text).strip()
        visible_text_len = len(visible_text)
        raw_html_size = len(page_content)

        # Empty or near-empty page (200 OK but no real content)
        if visible_text_len < 50:
            score = min(score + 15, 30)
            findings.append({
                "severity": "critical",
                "category": "empty_page",
                "detail": f"EMPTY PAGE — Server returned 200 OK but page has virtually no "
                          f"visible text ({visible_text_len} chars). HTML size: {raw_html_size} bytes. "
                          f"A legitimate business domain should have actual web content. "
                          f"Empty pages indicate compromised, gutted, or abandoned infrastructure."
            })
        elif visible_text_len < 200:
            score = min(score + 10, 30)
            findings.append({
                "severity": "high",
                "category": "near_empty_page",
                "detail": f"NEAR-EMPTY PAGE — Only {visible_text_len} characters of visible text. "
                          f"Minimal content on a sending domain is suspicious — may be a "
                          f"shell of a previously compromised site."
            })
        elif raw_html_size < 500:
            score = min(score + 3, 30)
            findings.append({
                "severity": "medium",
                "category": "thin_content",
                "detail": f"Extremely small page ({raw_html_size} bytes). Possible parked, "
                          f"hijacked, or stub domain."
            })

        # WordPress shell without content (WP markers but empty/gutted)
        if is_wordpress and visible_text_len < 300:
            score = min(score + 8, 30)
            findings.append({
                "severity": "critical",
                "category": "wp_empty_shell",
                "detail": f"GUTTED WORDPRESS SITE — WordPress CMS markers present but page "
                          f"has only {visible_text_len} chars of content. Classic indicator of a "
                          f"compromised WordPress site that was cleaned/wiped but not restored. "
                          f"Attackers often leave broken WP installations behind."
            })

        # Check for default/placeholder pages
        placeholder_signals = [
            "coming soon", "under construction", "parked domain",
            "this domain is for sale", "buy this domain",
            "default web page", "apache2 default page",
            "welcome to nginx", "it works!",
        ]
        for signal in placeholder_signals:
            if signal in content_lower:
                score = min(score + 5, 30)
                findings.append({
                    "severity": "high",
                    "category": "placeholder_page",
                    "detail": f"Placeholder/default page detected ('{signal}'). Domain may be "
                              f"parked, abandoned, or recently hijacked."
                })
                break

        hacklink_detected = score >= 15 or len(keywords_found) >= 2

        # ----- Generate Google Dork Queries -----
        google_dorks = self._generate_google_dorks(
            domain, keywords_found, injection_patterns, is_wordpress
        )

        return {
            "hacklink_detected": hacklink_detected,
            "score": min(score, 30),
            "keywords_found": keywords_found,
            "injection_patterns": injection_patterns,
            "suspicious_scripts": suspicious_scripts if suspicious_scripts else [],
            "wp_compromised": wp_compromised,
            "is_wordpress": is_wordpress,
            "is_cpanel": is_cpanel,
            "wp_plugins": wp_plugins,
            "vulnerable_plugins": vulnerable_plugins,
            "spam_link_count": spam_links,
            "google_dorks": google_dorks,
            "findings": findings,
            "fetch_status": fetch_status,
        }

    def _score_fetch_failure(self, domain, status, error, error_type, score, findings):
        """
        Score HTTP fetch failures as risk signals.
        A legitimate business domain that can't serve a web page is itself suspicious.
        """
        if status == 403:
            score += 8
            findings.append({
                "severity": "high",
                "category": "http_403",
                "detail": f"403 FORBIDDEN — {domain} blocks web access. Legitimate business "
                          f"sites don't typically block browsers. May indicate compromised "
                          f"infrastructure with attacker-configured access controls, or "
                          f"a domain that exists only for email-based attacks."
            })
        elif status == 401:
            score += 8
            findings.append({
                "severity": "high",
                "category": "http_401",
                "detail": f"401 UNAUTHORIZED — {domain} requires authentication. Very unusual "
                          f"for a domain being used as an email sending domain."
            })
        elif status == 404:
            score += 5
            findings.append({
                "severity": "medium",
                "category": "http_404",
                "detail": f"404 NOT FOUND — {domain} returns 404 at root. Domain exists in "
                          f"DNS but has no web content. Suspicious for an active sending domain."
            })
        elif status in (500, 502, 503, 504):
            score += 6
            findings.append({
                "severity": "high",
                "category": "http_server_error",
                "detail": f"SERVER ERROR ({status}) — {domain} is broken/down. A sending domain "
                          f"with failing web infrastructure is a signal of compromised or "
                          f"abandoned infrastructure being abused."
            })
        elif error_type == "timeout":
            score += 7
            findings.append({
                "severity": "high",
                "category": "http_timeout",
                "detail": f"CONNECTION TIMEOUT — {domain} did not respond. Sending domain with "
                          f"unreachable web server is suspicious. May indicate overwhelmed "
                          f"compromised infrastructure or intentionally non-web-facing setup."
            })
        elif error_type == "ssl_error":
            score += 8
            findings.append({
                "severity": "high",
                "category": "ssl_error",
                "detail": f"SSL/TLS ERROR — {domain} has certificate problems. Compromised "
                          f"domains often have expired, self-signed, or mismatched certificates "
                          f"when the attacker doesn't maintain the original SSL setup."
            })
        elif error_type == "connection_refused":
            score += 7
            findings.append({
                "severity": "high",
                "category": "connection_refused",
                "detail": f"CONNECTION REFUSED — {domain} actively refused connection. No web "
                          f"server running. Suspicious for a domain used for email sending."
            })
        elif error_type == "dns_failure":
            score += 10
            findings.append({
                "severity": "critical",
                "category": "dns_failure",
                "detail": f"DNS RESOLUTION FAILED — {domain} does not resolve. Domain may be "
                          f"expired, suspended, or using DNS that only resolves for email. "
                          f"Critical risk signal."
            })
        else:
            score += 5
            findings.append({
                "severity": "medium",
                "category": "fetch_failed",
                "detail": f"FETCH FAILED — {domain}: {error or 'unknown error'}. Unable to "
                          f"verify web presence of this sending domain."
            })

        return score, findings

    def _check_domain_name(self, domain: str) -> List[str]:
        """Check if the domain name itself contains hacklink-associated keywords."""
        found = []
        domain_lower = domain.lower().replace("-", "").replace(".", " ")
        # Also check with hyphens preserved
        domain_with_hyphens = domain.lower().replace(".", " ")

        # Check shorter, more specific keywords that are meaningful in domain names
        domain_name_keywords = [
            "hacklink", "bahis", "casino", "kumar", "slot", "betting",
            "escort", "cialis", "viagra", "nakliyat", "cekici",
            "porno", "bonus", "iddaa", "rulet", "poker",
        ]
        for kw in domain_name_keywords:
            if kw in domain_lower or kw in domain_with_hyphens:
                found.append(kw)
        return found

    def _fetch_content(self, url: str):
        """Fetch page content with safety limits. Returns (content, status_code)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })

        resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
        content = resp.read(self.max_content_size)
        status = resp.status if hasattr(resp, 'status') else 200
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = content.decode("latin-1", errors="replace")
        return text, status

    def _check_meta_anomalies(self, content: str) -> List[Dict]:
        """Check for suspicious meta tag patterns indicating compromise."""
        findings = []

        meta_kw = re.search(
            r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']',
            content, re.IGNORECASE
        )
        if meta_kw:
            kw_content = meta_kw.group(1).lower()
            spam_kws = [k for k in TURKISH_HACKLINK_KEYWORDS if k in kw_content]
            if spam_kws:
                findings.append({
                    "severity": "critical",
                    "category": "meta_injection",
                    "detail": f"Meta keywords contain hacklink/spam terms: {', '.join(spam_kws[:5])}"
                })

        lang_tag = re.search(r'<html[^>]*lang=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if lang_tag:
            page_lang = lang_tag.group(1).lower()[:2]
            has_turkish_kws = any(k in content.lower() for k in ["hacklink", "bahis", "canlı"])
            if has_turkish_kws and page_lang not in ["tr", "az"]:
                findings.append({
                    "severity": "high",
                    "category": "language_mismatch",
                    "detail": f"Turkish hacklink keywords on a '{page_lang}' language page. "
                              f"Strong indicator of injection/compromise."
                })

        return findings

    def _count_spam_outbound_links(self, content: str) -> int:
        """Count outbound links to known spam categories."""
        spam_domains_pattern = (
            r'href=["\']https?://[^"\']*(?:'
            r'bet|casino|slot|poker|bahis|kumar|escort|porno|xxx|sex|'
            r'viagra|cialis|pharma|pill|drug|weight.?loss|'
            r'hacklink|seo.?link|backlink.?service'
            r')[^"\']*["\']'
        )
        matches = re.findall(spam_domains_pattern, content, re.IGNORECASE)
        return len(matches)

    def _extract_wp_plugins(self, content: str) -> List[str]:
        """Extract WordPress plugin slugs from page source HTML."""
        plugin_pattern = r'wp-content/plugins/([a-zA-Z0-9_-]+)/'
        matches = re.findall(plugin_pattern, content, re.IGNORECASE)
        # Deduplicate preserving order
        seen = set()
        plugins = []
        for p in matches:
            slug = p.lower()
            if slug not in seen:
                seen.add(slug)
                plugins.append(slug)
        return plugins

    def _check_plugin_vulnerabilities(self, plugins: List[str]) -> List[Dict]:
        """
        Check extracted WordPress plugins against known vulnerable plugins
        frequently exploited in hacklink campaigns.
        Returns list of {plugin, risk, cve_ref, detail} dicts.
        """
        # Plugins commonly exploited in hacklink/SEO spam campaigns
        # Sources: WPScan, Wordfence, Sucuri reports
        KNOWN_VULNERABLE = {
            "revslider": {
                "risk": "CRITICAL",
                "cve": "CVE-2014-9734",
                "detail": "Revolution Slider — arbitrary file download/upload, "
                          "one of the most exploited WP plugins in hacklink campaigns.",
            },
            "developer-flavor-developer": {
                "risk": "CRITICAL",
                "cve": "CVE-2021-24990",
                "detail": "Developer Flavor — arbitrary file upload, hacklink injection vector.",
            },
            "contact-form-7": {
                "risk": "HIGH",
                "cve": "CVE-2020-35489",
                "detail": "Contact Form 7 — unrestricted file upload in older versions.",
            },
            "wp-file-manager": {
                "risk": "CRITICAL",
                "cve": "CVE-2020-25213",
                "detail": "WP File Manager — unauthenticated arbitrary file upload.",
            },
            "elementor": {
                "risk": "HIGH",
                "cve": "CVE-2022-29455",
                "detail": "Elementor — DOM XSS and privilege escalation in various versions.",
            },
            "wpgateway": {
                "risk": "CRITICAL",
                "cve": "CVE-2022-3180",
                "detail": "WP Gateway — unauthenticated privilege escalation.",
            },
            "tatsu": {
                "risk": "CRITICAL",
                "cve": "CVE-2021-25094",
                "detail": "Tatsu Builder — unauthenticated RCE via file upload.",
            },
            "wp-statistics": {
                "risk": "HIGH",
                "cve": "CVE-2022-25148",
                "detail": "WP Statistics — SQL injection in older versions.",
            },
            "essential-addons-for-elementor-lite": {
                "risk": "CRITICAL",
                "cve": "CVE-2023-32243",
                "detail": "Essential Addons for Elementor — privilege escalation.",
            },
            "woocommerce": {
                "risk": "MEDIUM",
                "cve": "CVE-2023-28121",
                "detail": "WooCommerce — authentication bypass in various versions.",
            },
            "yoast-seo": {
                "risk": "MEDIUM",
                "cve": "Multiple",
                "detail": "Yoast SEO — various XSS and SQL injection in older versions.",
            },
            "duplicator": {
                "risk": "CRITICAL",
                "cve": "CVE-2020-11738",
                "detail": "Duplicator — arbitrary file download and path traversal.",
            },
            "jetstyle": {
                "risk": "HIGH",
                "cve": "CVE-2021-24390",
                "detail": "JetStyle — arbitrary file upload vulnerability.",
            },
            "brizy": {
                "risk": "HIGH",
                "cve": "CVE-2021-38314",
                "detail": "Brizy Builder — information disclosure and file upload.",
            },
            "gravityforms": {
                "risk": "HIGH",
                "cve": "CVE-2023-28782",
                "detail": "Gravity Forms — object injection vulnerability.",
            },
            "formidable": {
                "risk": "HIGH",
                "cve": "CVE-2021-24836",
                "detail": "Formidable Forms — multiple injection vulnerabilities.",
            },
            "easy-wp-smtp": {
                "risk": "HIGH",
                "cve": "CVE-2019-8942",
                "detail": "Easy WP SMTP — debug log exposure, credential theft.",
            },
            "coming-soon": {
                "risk": "MEDIUM",
                "cve": "CVE-2021-24917",
                "detail": "SeedProd Coming Soon — subscriber data exposure.",
            },
            "jetstyle-developer": {
                "risk": "HIGH",
                "cve": "Multiple",
                "detail": "JetStyle Developer — common hacklink injection vector.",
            },
            "all-in-one-seo-pack": {
                "risk": "HIGH",
                "cve": "CVE-2021-25036",
                "detail": "All in One SEO — privilege escalation and SQL injection.",
            },
        }

        vulnerabilities = []
        for plugin in plugins:
            slug = plugin.lower().strip()
            if slug in KNOWN_VULNERABLE:
                vuln = KNOWN_VULNERABLE[slug]
                vulnerabilities.append({
                    "plugin": slug,
                    "risk": vuln["risk"],
                    "cve": vuln["cve"],
                    "detail": vuln["detail"],
                })
        return vulnerabilities

    def _generate_google_dorks(self, domain: str, keywords: List[str],
                                patterns: List[str], is_wordpress: bool) -> List[Dict]:
        """
        Generate Google dork queries to find other sites compromised with
        the same patterns, or to discover additional injected content.
        """
        dorks = []

        # 1. Find other sites with same injected keywords
        if keywords:
            kw_sample = " ".join(keywords[:3])
            dorks.append({
                "category": "find_other_victims",
                "query": f'intext:"{kw_sample}" -site:{domain}',
                "description": f"Find other sites injected with the same keywords: {kw_sample}",
            })

        # 2. Find cached/indexed hacklink content on this domain
        dorks.append({
            "category": "cached_content",
            "query": f'site:{domain} intext:"hacklink" OR intext:"bahis" OR intext:"casino"',
            "description": "Find indexed hacklink/gambling content on this domain",
        })

        # 3. Find hidden pages/directories
        dorks.append({
            "category": "hidden_pages",
            "query": f'site:{domain} inurl:wp-content OR inurl:wp-admin OR inurl:wp-includes',
            "description": "Find exposed WordPress paths that may contain injected content",
        })

        # 4. WordPress-specific dorks
        if is_wordpress:
            dorks.append({
                "category": "wp_exposed_files",
                "query": f'site:{domain} filetype:sql OR filetype:log OR filetype:bak',
                "description": "Find exposed database dumps, logs, or backups",
            })
            dorks.append({
                "category": "wp_login",
                "query": f'site:{domain} inurl:wp-login.php OR inurl:xmlrpc.php',
                "description": "Find WordPress login and XML-RPC endpoints",
            })

        # 5. Find injection patterns across the web
        if patterns:
            for pat in patterns[:2]:
                dorks.append({
                    "category": "injection_pattern",
                    "query": f'intext:"{pat}" -site:{domain}',
                    "description": f"Find other sites with same injection pattern: {pat}",
                })

        # 6. Link-based dork to find who links to this domain
        dorks.append({
            "category": "backlink_discovery",
            "query": f'intext:"{domain}" -site:{domain}',
            "description": f"Find sites that reference or link to {domain}",
        })

        # 7. Turkish hacklink-specific campaign dorks
        dorks.append({
            "category": "hacklink_campaign",
            "query": f'intext:"hacklink satın al" OR intext:"hacklink paneli" site:{domain}',
            "description": "Find Turkish hacklink marketplace content on this domain",
        })

        return dorks
