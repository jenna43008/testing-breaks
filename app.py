"""
Configuration management for Domain Sender Approval
"""

import json
import copy
import os
from pathlib import Path

# Config file location
CONFIG_DIR = Path(__file__).parent / "data"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Default configuration
DEFAULT_CONFIG = {
    "approve_threshold": 50,
    "timeout": 10.0,
    "check_rdap": True,
    "admin_password": "admin123",  # CHANGE THIS!
    "vt_api_key": "3976cc546c3ac01b8f50773c46a5c4a7e508709ae23b62ab4d82436222367d8",   # VirusTotal API key (hardcoded)
    "config_version": "7.2",              # Used for weight migration between versions
    
    "weights": {
        # === FRAUD/PHISHING SIGNALS (High weights - these SHOULD trigger DENY) ===
        "domain_blacklisted": 45,
        "ip_blacklisted": 40,
        "blacklist_inconclusive": 15,  # v6.2: DNSBL check timed out — "unknown" ≠ "clean"
        "typosquat_detected": 15,
        "brand_impersonation": 0,
        "malware_links": 100,
        "disposable_email": 40,
        "spf_pass_all": 0,           # +all allows anyone to spoof - security risk
        "domain_lt_7d": 0,           # Brand new domain - high risk
        "credential_form": 8,         # Building block — real risk comes from combo rules (20+ rules amplify this)
        "sensitive_fields": 10,
        
        # === VIRUSTOTAL REPUTATION ===
        "vt_malicious_high": 100,           # 5+ vendors flag as malicious — should deny alone
        "vt_malicious_medium": 100,         # 3-4 vendors flag as malicious
        "vt_malicious_low": 22,            # 1-2 vendors flag as malicious
        "vt_suspicious": 15,               # 3+ vendors flag as suspicious
        "vt_suspicious_low": 5,            # 1-2 vendors flag as suspicious
        "vt_negative_community": 25,       # Negative community reputation
        "vt_clean": 0,                    # Clean bill from 50+ vendors (bonus)
        
        # === HACKLINK / SEO SPAM DETECTION ===
        "hacklink_detected": 100,           # Hacklink SEO spam injection confirmed
        "hacklink_keywords": 25,           # Hacklink keywords present (below detection threshold)
        "hacklink_wp_compromised": 50,     # WordPress compromise indicators
        "hacklink_vulnerable_plugins": 25, # Known exploitable WP plugins
        "vuln_plugins_strong_mitigation": -18,   # Vuln plugins but 3+ legitimacy signals (established, app store, enterprise MX, etc.)
        "vuln_plugins_moderate_mitigation": -10,  # Vuln plugins but 2 legitimacy signals
        "hacklink_spam_links": 35,         # 5+ hidden spam links in content
        "malicious_script": 100,            # SocGholish/FakeUpdates/obfuscated script injection — HIGH confidence (5+ multi-signal score)
        "malicious_script_medium": 40,      # v7.2: MEDIUM confidence malicious script (3-4 multi-signal score) — log + moderate penalty
        "hidden_injection": 100,            # CSS-hidden content injection (hacklink fingerprint) — confirmed compromise
        "hidden_injection_css_only": 0,     # CSS hiding patterns (display:none etc.) without confirmed injection — too common on legitimate sites
        "cpanel_detected": 25,              # cPanel hosting (common hacklink target, not malicious alone)
        
        # === TRANSFER LOCK / DOMAIN TAKEOVER ===
        "transfer_lock_recent": 35,        # Transfer lock recently added (post-compromise lockdown signal)
        "whois_recently_updated": 10,      # WHOIS updated in last 30 days
        
        # === EMPTY PAGE ===
        "empty_page": 20,                  # Reachable domain with empty/near-empty content
        
        # === CERTIFICATE TRANSPARENCY ===
        "ct_recent_issuance": 10,          # Cert issued within last 7 days
        "ct_no_history": 15,               # Zero certs in CT logs
        
        # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
        "suspicious_prefix": 15,           # app-, my-, support-, login-, etc.
        "suspicious_suffix": 15,           # account, setup, cancellation, etc.
        "tech_support_tld": 20,            # .support, .tech, .help, etc.
        "domain_brand_impersonation": 0,  # Brand name IN domain (app-spectrum.com)
        "brand_spoofing_keyword": 20,      # Brand + phishing keyword (easyjetconnect, amazonverify)
        
        # === TLD VARIANT SPOOFING DETECTION ===
        "tld_variant_spoofing": 45,        # Signup domain is TLD variant of established business
        
        # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
        "hijack_path_pattern": 25,         # /tunnel/, /bid/, /secure/ paths
        "doc_sharing_lure": 25,            # "Secure Document Sharing" content
        "phishing_js_behavior": 25,        # atob(), hash extraction, etc.
        "phishing_infra_redirect": 35,     # Redirect to workers.dev, etc.
        "email_tracking_url": 20,          # Email in URL hash (tracking)
        
        # === E-COMMERCE / RETAIL SCAM INDICATORS ===
        "retail_scam_tld": 12,             # .shop, .store, .sale, etc.
        "ecommerce_no_identity": 15,       # E-commerce site with no business identity
        "cross_domain_brand_link": 18,     # Links to same-brand different TLD (clone indicator)
        "ecommerce_missing_policies": 8,   # E-commerce without terms/refund policy
        
        # === DELIVERABILITY CONCERNS (Low weights - warn but don't deny alone) ===
        "no_spf": 0,                  # Missing SPF - their problem, not fraud
        "spf_neutral_all": 0,         # ?all - weak but not dangerous
        "spf_softfail_all": 0,        # ~all - totally acceptable, very minor
        "spf_too_many_lookups": 0,
        "spf_syntax_error": 0,
        "no_dmarc": 0,               # Missing DMARC - deliverability issue only
        "dmarc_p_none": 0,            # p=none - tells receivers to do nothing about failures (raised from 5)
        "dmarc_no_rua": 0,            # No reporting - trivial
        "dmarc_syntax_error": 0,
        "no_dkim": 0,                # Missing DKIM - strong risk signal per disabled apps data (raised from 6)
        "no_mx": 0,                   # No MX - can't receive bounces
        "null_mx": 0,
        "mx_free_provider": 6,
        "mx_mail_prefix": 4,              # v6.2: MX is mail.{domain} — phishing template fingerprint
        "spf_no_external_includes": 0,    # v6.2: SPF exists but no real provider (Google/M365/etc.)
        
        # === INFRASTRUCTURE CONCERNS (Low weights) ===
        "no_ptr": 0,                  # Missing PTR - minor
        "ptr_mismatch": 15,
        "no_https": 25,                # No HTTPS - minor concern
        "tls_handshake_failed": 40,   # SSL handshake fails (cipher/protocol mismatch)  # v4.4
        "tls_connection_failed": 30,   # Can't reach port 443 (no HTTPS service)          # v4.4
        "http_accessible": 15,
        "cert_self_signed": 6,
        "cert_expired": 8,
        "cert_wrong_host": 15,
        
        # === DOMAIN AGE (Moderate for very new, low otherwise) ===
        "domain_lt_30d": 0,          # 7-30 days old - moderate concern
        "domain_lt_90d": 0,           # 30-90 days old - minor concern
        
        # Domain age WITH content risk (only fires when age + risky content co-occur)
        "new_domain_with_risk": 40,              # Created today/yesterday + content risk signals
        "young_domain_with_risk_7d": 25,         # 2-7 days old + content risk signals
        "young_domain_with_risk_30d": 10,        # 8-30 days old + content risk signals
        "young_domain_with_risk_90d": 4,         # 31-90 days old + content risk signals
        
        "suspicious_tld": 15,          # High-abuse TLD
        "free_email_domain": 15,      # Sending from gmail.com etc
        "free_hosting": 6,
        "url_shortener": 20,
        
        # === REDIRECT/CLOAKING CONCERNS ===
        "redirect_chain_2plus": 15,
        "redirect_chain_3plus": 15,
        "redirect_cross_domain": 15,
        "redirect_temp_302_307": 15,
        
        # === SUSPICIOUS BEHAVIOR (Higher weights - actual red flags) ===
        "status_401_unauthorized": 25,    # 401 on public site - unusual
        "status_403_cloaking": 25,
        "status_429_throttling": 15,
        "status_503_disposable": 25,
        "status_5xx_errors": 10,
        "access_restricted": 15,          # 401 or 403 on what should be public domain
        "minimal_shell": 15,
        "js_redirect": 3,             # Ubiquitous in modern web — combo fuel only (shell+redirect, cloaking+redirect)
        
        # Mitigations (negative weights — reduce score when strong email auth present)
        "minimal_shell_email_auth_mitigated": -8,   # Shell site with SPF -all + DMARC reject — less likely phishing
        "js_redirect_email_auth_mitigated": -3,      # JS redirect with SPF -all + DMARC reject — nets to ~0
        "meta_refresh": 5,
        "external_js_loader": 6,
        "obfuscated_js": 15,
        "phishing_paths": 25,
        "phishing_kit_filename_strong": 22,   # gate.php, process.php — almost never legitimate
        "phishing_kit_detected": 15,          # Composite: multiple kit signals confirm a live kit
        "exfil_drop_script": 30,              # Telegram/Discord/base64 exfil in page source
        "form_posts_external": 10,
        "suspicious_iframe": 15,
        "parking_page": 20,
        
        # === CORPORATE TRUST SIGNALS (Missing signals indicate opaque entity) ===
        "missing_trust_signals": 20,       # No about/contact/privacy pages
        "opaque_entity": 20,              # Access blocked + no trust signals = high risk
        
        # === BONUSES (Reduce score) ===
        "has_bimi": -15,
        "has_mta_sts": -10,
        
        # === APP STORE PRESENCE BONUSES (Legitimacy signal) ===
        # Rare for bad actors to maintain real app store presence
        "app_store_high": -15,    # Verified deep links (AASA/assetlinks) or multiple signals
        "app_store_medium": 0,   # Page links to app stores or iTunes API match (reduced - easy to fake)
        "app_store_low": 0,       # Keyword-only match in iTunes (disabled - too weak, 66% of disabled apps had this)
        
        # === HOSTING PROVIDER PENALTIES ===
        # Budget shared hosts and free hosts have higher spam/phishing rates
        "hosting_budget_shared": 10,   # Hostinger, GoDaddy shared, Namecheap shared, etc.
        "hosting_free": 12,           # 000webhost, InfinityFree, AwardSpace, etc.
        "hosting_suspect": 20,        # Known bulletproof / abuse-tolerant hosts
        "hosting_platform": 20,        # v6.2: Dev platforms (Render, Netlify, Vercel) — mild signal
        
        # === NAMESERVER RISK SIGNALS ===
        "ns_parking": 15,             # Domain delegated to parking/placeholder NS (sedoparking, bodis, etc.)
        "ns_dynamic_dns": 25,         # Domain delegated to dynamic DNS provider (noip, dyndns, etc.)
        "ns_free_dns": 8,             # Domain using free/anonymous authoritative DNS
        "ns_lame_delegation": 20,     # Zero NS records — broken/abandoned domain
        "ns_single_ns": 5,            # Only 1 NS record — unusual, possible fragile/temporary setup
        
        # === MX PROVIDER SCORING (v4.7) ===
        "mx_disposable": 20,          # Disposable/cheap MX (Titan, ImprovMX, Hostinger email, etc.)
        "mx_selfhosted": 20,           # Self-hosted MX on same domain/IP - no provider oversight
        "mx_enterprise_bonus": -10,    # Enterprise MX (Google Workspace, M365, Proofpoint) = legitimacy signal
    },
    
    # ==========================================================================
    # UNIFIED RULES ENGINE
    # ==========================================================================
    # All scoring beyond base weights. Former "combos" are rules with categories.
    # Each rule: name, score, label, category, enabled, if_all, if_any, if_not
    "rules": [
        # --- Brand Impersonation (27 rules) ---
        {"name": "combo_brand_domain_cred_form", "score": 0, "label": "domain brand impersonation + credential form", "category": "Brand Impersonation", "enabled": True, "if_all": ["domain_brand_impersonation", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_brand_domain_new_30d", "score": 0, "label": "domain brand impersonation + domain <30d", "category": "Brand Impersonation", "enabled": True, "if_all": ["domain_brand_impersonation", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_brand_domain_no_https", "score": 0, "label": "domain brand impersonation + no https", "category": "Brand Impersonation", "enabled": True, "if_all": ["domain_brand_impersonation", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_brand_domain_sus_prefix", "score": 0, "label": "domain brand impersonation + suspicious prefix", "category": "Brand Impersonation", "enabled": True, "if_all": ["domain_brand_impersonation", "suspicious_prefix"], "if_any": [], "if_not": []},
        {"name": "combo_brand_domain_sus_suffix", "score": 0, "label": "domain brand impersonation + suspicious suffix", "category": "Brand Impersonation", "enabled": True, "if_all": ["domain_brand_impersonation", "suspicious_suffix"], "if_any": [], "if_not": []},
        {"name": "combo_brand_domain_techsupport_tld", "score": 0, "label": "domain brand impersonation + tech support tld", "category": "Brand Impersonation", "enabled": True, "if_all": ["domain_brand_impersonation", "tech_support_tld"], "if_any": [], "if_not": []},
        {"name": "combo_brand_imp_cred_form", "score": 20, "label": "brand impersonation + credential form", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_impersonation", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_brand_imp_new_30d", "score": 0, "label": "brand impersonation + domain <30d", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_impersonation", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_brand_imp_no_https", "score": 20, "label": "brand impersonation + no https", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_impersonation", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_budget_host", "score": 0, "label": "brand spoofing keyword + hosting budget shared", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "hosting_budget_shared"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_cred_form", "score": 0, "label": "brand spoofing keyword + credential form", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_disposable_mx", "score": 12, "label": "brand spoofing keyword + mx disposable", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "mx_disposable"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_free_host", "score": 15, "label": "brand spoofing keyword + hosting free", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "hosting_free"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_new_30d", "score": 0, "label": "brand spoofing keyword + domain <30d", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_new_7d", "score": 25, "label": "brand spoofing keyword + domain <7d", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_no_dkim", "score": 0, "label": "brand spoofing keyword + no dkim", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_no_dmarc", "score": 0, "label": "brand spoofing keyword + no dmarc", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "no_dmarc"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_no_https", "score": 15, "label": "brand spoofing keyword + no https", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_no_trust", "score": 12, "label": "brand spoofing keyword + missing trust signals", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "missing_trust_signals"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_parked", "score": 15, "label": "brand spoofing keyword + parking page", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "parking_page"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_platform_host", "score": 12, "label": "brand spoofing keyword + hosting platform", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "hosting_platform"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_self_mx", "score": 12, "label": "brand spoofing keyword + mx selfhosted", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "mx_selfhosted"], "if_any": [], "if_not": []},
        {"name": "combo_brand_keyword_shell_site", "score": 18, "label": "brand spoofing keyword + minimal shell", "category": "Brand Impersonation", "enabled": True, "if_all": ["brand_spoofing_keyword", "minimal_shell"], "if_any": [], "if_not": []},
        {"name": "combo_budget_host_brand_imp", "score": 18, "label": "hosting budget shared + brand impersonation", "category": "Brand Impersonation", "enabled": True, "if_all": ["hosting_budget_shared", "brand_impersonation"], "if_any": [], "if_not": []},
        {"name": "combo_free_host_brand_imp", "score": 22, "label": "hosting free + brand impersonation", "category": "Brand Impersonation", "enabled": True, "if_all": ["hosting_free", "brand_impersonation"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_brand_imp", "score": 25, "label": "status 403 cloaking + brand impersonation", "category": "Brand Impersonation", "enabled": True, "if_all": ["status_403_cloaking", "brand_impersonation"], "if_any": [], "if_not": []},
        {"name": "combo_suspect_host_brand_imp", "score": 28, "label": "hosting suspect + brand impersonation", "category": "Brand Impersonation", "enabled": True, "if_all": ["hosting_suspect", "brand_impersonation"], "if_any": [], "if_not": []},

        # --- Email Auth Weakness (14 rules) ---
        {"name": "combo_disposable_no_spf", "score": 0, "label": "disposable email + no spf", "category": "Email Auth Weakness", "enabled": True, "if_all": ["disposable_email", "no_spf"], "if_any": [], "if_not": []},
        {"name": "combo_no_dkim_new_30d", "score": 0, "label": "no dkim + domain <30d", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_dkim", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_no_dkim_no_dmarc", "score": 0, "label": "no dkim + no dmarc", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_dkim", "no_dmarc"], "if_any": [], "if_not": []},
        {"name": "combo_no_dkim_weak_dmarc", "score": 0, "label": "no dkim + dmarc p none", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_dkim", "dmarc_p_none"], "if_any": [], "if_not": []},
        {"name": "combo_no_dkim_weak_dmarc_spf_soft", "score": 0, "label": "no dkim + dmarc p none + spf softfail all", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_dkim", "dmarc_p_none", "spf_softfail_all"], "if_any": [], "if_not": []},
        {"name": "combo_no_dmarc_new_30d", "score": 0, "label": "no dmarc + domain <30d", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_dmarc", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_no_dmarc_new_7d", "score": 0, "label": "no dmarc + domain <7d", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_dmarc", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_no_spf_new_30d", "score": 0, "label": "no spf + domain <30d", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_spf", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_no_spf_new_7d", "score": 0, "label": "no spf + domain <7d", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_spf", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_no_spf_no_dkim", "score": 0, "label": "no spf + no dkim", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_spf", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_no_spf_no_dmarc", "score": 0, "label": "no spf + no dmarc", "category": "Email Auth Weakness", "enabled": True, "if_all": ["no_spf", "no_dmarc"], "if_any": [], "if_not": []},
        {"name": "combo_spf_no_ext_mail_prefix_mx", "score": 0, "label": "spf no external includes + mx mail prefix", "category": "Email Auth Weakness", "enabled": True, "if_all": ["spf_no_external_includes", "mx_mail_prefix"], "if_any": [], "if_not": []},
        {"name": "combo_spf_no_ext_self_mx", "score": 0, "label": "spf no external includes + mx selfhosted", "category": "Email Auth Weakness", "enabled": True, "if_all": ["spf_no_external_includes", "mx_selfhosted"], "if_any": [], "if_not": []},
        {"name": "combo_spf_open_no_dmarc", "score": 0, "label": "spf pass all + no dmarc", "category": "Email Auth Weakness", "enabled": True, "if_all": ["spf_pass_all", "no_dmarc"], "if_any": [], "if_not": []},

        # --- Fraud / Blacklist (5 + 5 rules) ---
        {"name": "combo_blacklisted_new_30d", "score": 30, "label": "domain blacklisted + domain <30d", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["domain_blacklisted", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_ptr_bad_blacklisted", "score": 10, "label": "ptr mismatch + domain blacklisted", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["ptr_mismatch", "domain_blacklisted"], "if_any": [], "if_not": []},
        {"name": "combo_typosquat_cred_form", "score": 35, "label": "typosquat detected + credential form", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["typosquat_detected", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_typosquat_new_30d", "score": 28, "label": "typosquat detected + domain <30d", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["typosquat_detected", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_typosquat_redir_chain", "score": 25, "label": "typosquat detected + redirect chain 2plus", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["typosquat_detected", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        # v6.2: Inconclusive blacklist combos — amplify penalty when combined with other red flags
        {"name": "combo_bl_inconclusive_new_30d", "score": 10, "label": "blacklist inconclusive + domain <30d", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["blacklist_inconclusive", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_bl_inconclusive_no_dkim", "score": 8, "label": "blacklist inconclusive + no dkim", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["blacklist_inconclusive", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_bl_inconclusive_weak_auth", "score": 12, "label": "blacklist inconclusive + no dkim + dmarc p=none", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["blacklist_inconclusive", "no_dkim", "dmarc_p_none"], "if_any": [], "if_not": []},
        {"name": "combo_bl_inconclusive_self_mx", "score": 8, "label": "blacklist inconclusive + self-hosted MX", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["blacklist_inconclusive", "mx_selfhosted"], "if_any": [], "if_not": []},
        {"name": "combo_bl_inconclusive_shell", "score": 10, "label": "blacklist inconclusive + minimal shell site", "category": "Fraud / Blacklist", "enabled": True, "if_all": ["blacklist_inconclusive", "minimal_shell"], "if_any": [], "if_not": []},

        # --- General Risk (19 rules) ---
        {"name": "combo_cred_form_no_https", "score": 12, "label": "credential form + no https", "category": "General Risk", "enabled": True, "if_all": ["credential_form", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_cross_redir_new_30d", "score": 12, "label": "redirect cross domain + domain <30d", "category": "General Risk", "enabled": True, "if_all": ["redirect_cross_domain", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_cross_redir_new_7d", "score": 18, "label": "redirect cross domain + domain <7d", "category": "General Risk", "enabled": True, "if_all": ["redirect_cross_domain", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_disposable_new_30d", "score": 18, "label": "disposable email + domain <30d", "category": "General Risk", "enabled": True, "if_all": ["disposable_email", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_free_email_cred_form", "score": 10, "label": "free email domain + credential form", "category": "General Risk", "enabled": True, "if_all": ["free_email_domain", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_new_30d_redir_chain", "score": 12, "label": "domain <30d + redirect chain 2plus", "category": "General Risk", "enabled": True, "if_all": ["domain_lt_30d", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_new_30d_temp_redir", "score": 10, "label": "domain <30d + redirect temp 302 307", "category": "General Risk", "enabled": True, "if_all": ["domain_lt_30d", "redirect_temp_302_307"], "if_any": [], "if_not": []},
        {"name": "combo_new_7d_redir_chain", "score": 20, "label": "domain <7d + redirect chain 2plus", "category": "General Risk", "enabled": True, "if_all": ["domain_lt_7d", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_new_7d_temp_redir", "score": 18, "label": "domain <7d + redirect temp 302 307", "category": "General Risk", "enabled": True, "if_all": ["domain_lt_7d", "redirect_temp_302_307"], "if_any": [], "if_not": []},
        {"name": "combo_no_https_cross_redir", "score": 15, "label": "no https + redirect cross domain", "category": "General Risk", "enabled": True, "if_all": ["no_https", "redirect_cross_domain"], "if_any": [], "if_not": []},
        {"name": "combo_no_https_redir_chain", "score": 18, "label": "no https + redirect chain 2plus", "category": "General Risk", "enabled": True, "if_all": ["no_https", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_no_https_temp_redir", "score": 15, "label": "no https + redirect temp 302 307", "category": "General Risk", "enabled": True, "if_all": ["no_https", "redirect_temp_302_307"], "if_any": [], "if_not": []},
        {"name": "combo_no_mx_new_30d", "score": 6, "label": "no mx + domain <30d", "category": "General Risk", "enabled": True, "if_all": ["no_mx", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_no_ptr_new_30d", "score": 4, "label": "no ptr + domain <30d", "category": "General Risk", "enabled": True, "if_all": ["no_ptr", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_shell_site_cred_form", "score": 15, "label": "minimal shell + credential form", "category": "General Risk", "enabled": True, "if_all": ["minimal_shell", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_shell_site_js_redir", "score": 18, "label": "minimal shell + js redirect", "category": "General Risk", "enabled": True, "if_all": ["minimal_shell", "js_redirect"], "if_any": [], "if_not": []},
        {"name": "combo_shell_site_new_30d", "score": 12, "label": "minimal shell + domain <30d", "category": "General Risk", "enabled": True, "if_all": ["minimal_shell", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_sus_tld_new_30d", "score": 10, "label": "suspicious tld + domain <30d", "category": "General Risk", "enabled": True, "if_all": ["suspicious_tld", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_sus_tld_redir_chain", "score": 10, "label": "suspicious tld + redirect chain 2plus", "category": "General Risk", "enabled": True, "if_all": ["suspicious_tld", "redirect_chain_2plus"], "if_any": [], "if_not": []},

        # --- HTTP Status Evasion (43 rules) ---
        {"name": "combo_http_401_cred_form", "score": 18, "label": "status 401 unauthorized + credential form", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_http_403", "score": 18, "label": "status 401 unauthorized + status 403 cloaking", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "status_403_cloaking"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_http_503", "score": 15, "label": "status 401 unauthorized + status 503 disposable", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "status_503_disposable"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_new_30d", "score": 12, "label": "status 401 unauthorized + domain <30d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_new_7d", "score": 18, "label": "status 401 unauthorized + domain <7d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_no_https", "score": 15, "label": "status 401 unauthorized + no https", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_redir_chain", "score": 15, "label": "status 401 unauthorized + redirect chain 2plus", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_shell_site", "score": 15, "label": "status 401 unauthorized + minimal shell", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "minimal_shell"], "if_any": [], "if_not": []},
        {"name": "combo_http_401_temp_redir", "score": 12, "label": "status 401 unauthorized + redirect temp 302 307", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_401_unauthorized", "redirect_temp_302_307"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_cred_form", "score": 20, "label": "status 403 cloaking + credential form", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_cross_redir", "score": 20, "label": "status 403 cloaking + redirect cross domain", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "redirect_cross_domain"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_doc_lure", "score": 20, "label": "status 403 cloaking + doc sharing lure", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "doc_sharing_lure"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_hijack_path", "score": 22, "label": "status 403 cloaking + hijack path pattern", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "hijack_path_pattern"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_http_429", "score": 15, "label": "status 403 cloaking + status 429 throttling", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "status_429_throttling"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_http_503", "score": 18, "label": "status 403 cloaking + status 503 disposable", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "status_503_disposable"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_js_redir", "score": 20, "label": "status 403 cloaking + js redirect", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "js_redirect"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_new_30d", "score": 15, "label": "status 403 cloaking + domain <30d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_new_7d", "score": 25, "label": "status 403 cloaking + domain <7d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_no_https", "score": 18, "label": "status 403 cloaking + no https", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_phish_infra", "score": 28, "label": "status 403 cloaking + phishing infra redirect", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "phishing_infra_redirect"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_phish_js", "score": 22, "label": "status 403 cloaking + phishing js behavior", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "phishing_js_behavior"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_phish_paths", "score": 22, "label": "status 403 cloaking + phishing paths", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "phishing_paths"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_redir_chain", "score": 22, "label": "status 403 cloaking + redirect chain 2plus", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_shell_site", "score": 22, "label": "status 403 cloaking + minimal shell", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "minimal_shell"], "if_any": [], "if_not": []},
        {"name": "combo_http_403_temp_redir", "score": 22, "label": "status 403 cloaking + redirect temp 302 307", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_403_cloaking", "redirect_temp_302_307"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_cred_form", "score": 15, "label": "status 429 throttling + credential form", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_http_503", "score": 12, "label": "status 429 throttling + status 503 disposable", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "status_503_disposable"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_new_30d", "score": 10, "label": "status 429 throttling + domain <30d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_new_7d", "score": 15, "label": "status 429 throttling + domain <7d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_no_https", "score": 12, "label": "status 429 throttling + no https", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_redir_chain", "score": 12, "label": "status 429 throttling + redirect chain 2plus", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_shell_site", "score": 15, "label": "status 429 throttling + minimal shell", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "minimal_shell"], "if_any": [], "if_not": []},
        {"name": "combo_http_429_temp_redir", "score": 12, "label": "status 429 throttling + redirect temp 302 307", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_429_throttling", "redirect_temp_302_307"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_cred_form", "score": 18, "label": "status 503 disposable + credential form", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_cross_redir", "score": 15, "label": "status 503 disposable + redirect cross domain", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "redirect_cross_domain"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_hijack_path", "score": 15, "label": "status 503 disposable + hijack path pattern", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "hijack_path_pattern"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_new_30d", "score": 12, "label": "status 503 disposable + domain <30d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_new_7d", "score": 18, "label": "status 503 disposable + domain <7d", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_no_https", "score": 15, "label": "status 503 disposable + no https", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "no_https"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_phish_infra", "score": 22, "label": "status 503 disposable + phishing infra redirect", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "phishing_infra_redirect"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_redir_chain", "score": 15, "label": "status 503 disposable + redirect chain 2plus", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "redirect_chain_2plus"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_shell_site", "score": 15, "label": "status 503 disposable + minimal shell", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "minimal_shell"], "if_any": [], "if_not": []},
        {"name": "combo_http_503_temp_redir", "score": 15, "label": "status 503 disposable + redirect temp 302 307", "category": "HTTP Status Evasion", "enabled": True, "if_all": ["status_503_disposable", "redirect_temp_302_307"], "if_any": [], "if_not": []},

        # --- Hosting Risk (16 rules) ---
        {"name": "combo_budget_host_cred_form", "score": 15, "label": "hosting budget shared + credential form", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_budget_shared", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_budget_host_new_30d", "score": 12, "label": "hosting budget shared + domain <30d", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_budget_shared", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_budget_host_new_7d", "score": 18, "label": "hosting budget shared + domain <7d", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_budget_shared", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_budget_host_no_dkim", "score": 6, "label": "hosting budget shared + no dkim", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_budget_shared", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_budget_host_no_dmarc", "score": 6, "label": "hosting budget shared + no dmarc", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_budget_shared", "no_dmarc"], "if_any": [], "if_not": []},
        {"name": "combo_budget_host_no_spf", "score": 6, "label": "hosting budget shared + no spf", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_budget_shared", "no_spf"], "if_any": [], "if_not": []},
        {"name": "combo_free_host_cred_form", "score": 18, "label": "hosting free + credential form", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_free", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_free_host_new_30d", "score": 15, "label": "hosting free + domain <30d", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_free", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_platform_host_mail_prefix_mx", "score": 8, "label": "hosting platform + mx mail prefix", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_platform", "mx_mail_prefix"], "if_any": [], "if_not": []},
        {"name": "combo_platform_host_no_dkim", "score": 5, "label": "hosting platform + no dkim", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_platform", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_platform_host_self_mx", "score": 6, "label": "hosting platform + mx selfhosted", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_platform", "mx_selfhosted"], "if_any": [], "if_not": []},
        {"name": "combo_platform_host_self_mx_no_dkim", "score": 10, "label": "hosting platform + mx selfhosted + no dkim", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_platform", "mx_selfhosted", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_suspect_host_cred_form", "score": 25, "label": "hosting suspect + credential form", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_suspect", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_suspect_host_new_30d", "score": 22, "label": "hosting suspect + domain <30d", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_suspect", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_suspect_host_new_7d", "score": 28, "label": "hosting suspect + domain <7d", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_suspect", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_suspect_host_no_https", "score": 18, "label": "hosting suspect + no https", "category": "Hosting Risk", "enabled": True, "if_all": ["hosting_suspect", "no_https"], "if_any": [], "if_not": []},

        # --- Nameserver Risk (8 rules) ---
        {"name": "combo_ns_dynamic_new_30d", "score": 20, "label": "dynamic DNS NS + domain <30d", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_dynamic_dns", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_ns_dynamic_cred_form", "score": 22, "label": "dynamic DNS NS + credential form", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_dynamic_dns", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_ns_dynamic_no_mx", "score": 10, "label": "dynamic DNS NS + no MX", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_dynamic_dns", "no_mx"], "if_any": [], "if_not": []},
        {"name": "combo_ns_parking_new_90d", "score": 12, "label": "parking NS + domain <90d", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_parking", "domain_lt_90d"], "if_any": [], "if_not": []},
        {"name": "combo_ns_parking_no_trust", "score": 10, "label": "parking NS + missing trust signals", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_parking", "missing_trust_signals"], "if_any": [], "if_not": []},
        {"name": "combo_ns_lame_no_mx", "score": 15, "label": "lame delegation + no MX", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_lame_delegation", "no_mx"], "if_any": [], "if_not": []},
        {"name": "combo_ns_free_no_dkim", "score": 6, "label": "free DNS NS + no DKIM", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_free_dns", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_ns_single_new_30d", "score": 8, "label": "single NS + domain <30d", "category": "Nameserver Risk", "enabled": True, "if_all": ["ns_single_ns", "domain_lt_30d"], "if_any": [], "if_not": []},

        # --- Phishing Kit Detection (8 rules) ---
        # Weak kit filenames (login.php, verify.php) are zero-scored alone —
        # only combo rules give them weight, requiring a second corroborating signal.
        {"name": "combo_kit_weak_cred_form", "score": 18, "label": "kit filename (weak) + credential form", "category": "Phishing Kit", "enabled": True, "if_all": ["phishing_kit_filename_weak", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_kit_weak_brand", "score": 18, "label": "kit filename (weak) + brand impersonation", "category": "Phishing Kit", "enabled": True, "if_all": ["phishing_kit_filename_weak", "brand_impersonation"], "if_any": [], "if_not": []},
        {"name": "combo_kit_weak_phish_path", "score": 15, "label": "kit filename (weak) + phishing path", "category": "Phishing Kit", "enabled": True, "if_all": ["phishing_kit_filename_weak", "phishing_paths"], "if_any": [], "if_not": []},
        {"name": "combo_kit_weak_exfil", "score": 25, "label": "kit filename (weak) + exfil drop script", "category": "Phishing Kit", "enabled": True, "if_all": ["phishing_kit_filename_weak", "exfil_drop_script"], "if_any": [], "if_not": []},
        {"name": "combo_kit_strong_cred_form", "score": 20, "label": "kit filename (strong) + credential form", "category": "Phishing Kit", "enabled": True, "if_all": ["phishing_kit_filename_strong", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_kit_strong_brand", "score": 22, "label": "kit filename (strong) + brand impersonation", "category": "Phishing Kit", "enabled": True, "if_all": ["phishing_kit_filename_strong", "brand_impersonation"], "if_any": [], "if_not": []},
        {"name": "combo_exfil_cred_form", "score": 25, "label": "exfil drop script + credential form", "category": "Phishing Kit", "enabled": True, "if_all": ["exfil_drop_script", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_exfil_brand", "score": 25, "label": "exfil drop script + brand impersonation", "category": "Phishing Kit", "enabled": True, "if_all": ["exfil_drop_script", "brand_impersonation"], "if_any": [], "if_not": []},

        # --- MX Provider Risk (9 rules) ---
        {"name": "combo_disposable_mx_budget_host", "score": 8, "label": "mx disposable + hosting budget shared", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_disposable", "hosting_budget_shared"], "if_any": [], "if_not": []},
        {"name": "combo_disposable_mx_no_dkim", "score": 8, "label": "mx disposable + no dkim", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_disposable", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_disposable_mx_weak_dmarc", "score": 6, "label": "mx disposable + dmarc p none", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_disposable", "dmarc_p_none"], "if_any": [], "if_not": []},
        {"name": "combo_mail_prefix_mx_no_dkim", "score": 5, "label": "mx mail prefix + no dkim", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_mail_prefix", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_mail_prefix_mx_no_dkim_weak_dmarc", "score": 8, "label": "mx mail prefix + no dkim + dmarc p none", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_mail_prefix", "no_dkim", "dmarc_p_none"], "if_any": [], "if_not": []},
        {"name": "combo_mail_prefix_mx_no_dkim_weak_dmarc_no_ptr", "score": 10, "label": "mx mail prefix + no dkim + dmarc p none + no ptr", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_mail_prefix", "no_dkim", "dmarc_p_none", "no_ptr"], "if_any": [], "if_not": []},
        {"name": "combo_mail_prefix_mx_no_ptr", "score": 4, "label": "mx mail prefix + no ptr", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_mail_prefix", "no_ptr"], "if_any": [], "if_not": []},
        {"name": "combo_self_mx_budget_host", "score": 6, "label": "mx selfhosted + hosting budget shared", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_selfhosted", "hosting_budget_shared"], "if_any": [], "if_not": []},
        {"name": "combo_self_mx_no_dkim", "score": 6, "label": "mx selfhosted + no dkim", "category": "MX Provider Risk", "enabled": True, "if_all": ["mx_selfhosted", "no_dkim"], "if_any": [], "if_not": []},

        # --- Opaque Entity (5 rules) ---
        {"name": "combo_no_trust_new_30d", "score": 12, "label": "missing trust signals + domain <30d", "category": "Opaque Entity", "enabled": True, "if_all": ["missing_trust_signals", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_opaque_new_30d", "score": 25, "label": "opaque entity + domain <30d", "category": "Opaque Entity", "enabled": True, "if_all": ["opaque_entity", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_opaque_new_90d", "score": 18, "label": "opaque entity + domain <90d", "category": "Opaque Entity", "enabled": True, "if_all": ["opaque_entity", "domain_lt_90d"], "if_any": [], "if_not": []},
        {"name": "combo_restricted_new_30d", "score": 15, "label": "access restricted + domain <30d", "category": "Opaque Entity", "enabled": True, "if_all": ["access_restricted", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_restricted_no_trust", "score": 15, "label": "access restricted + missing trust signals", "category": "Opaque Entity", "enabled": True, "if_all": ["access_restricted", "missing_trust_signals"], "if_any": [], "if_not": []},

        # --- Phishing Infrastructure (13 rules) ---
        {"name": "combo_doc_lure_hijack_path", "score": 22, "label": "doc sharing lure + hijack path pattern", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["doc_sharing_lure", "hijack_path_pattern"], "if_any": [], "if_not": []},
        {"name": "combo_doc_lure_phish_js", "score": 25, "label": "doc sharing lure + phishing js behavior", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["doc_sharing_lure", "phishing_js_behavior"], "if_any": [], "if_not": []},
        {"name": "combo_email_track_phish_js", "score": 25, "label": "email tracking url + phishing js behavior", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["email_tracking_url", "phishing_js_behavior"], "if_any": [], "if_not": []},
        {"name": "combo_hijack_path_cred_form", "score": 20, "label": "hijack path pattern + credential form", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["hijack_path_pattern", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_hijack_path_established", "score": 18, "label": "hijack path pattern + domain >1yr", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["hijack_path_pattern", "domain_gt_1yr"], "if_any": [], "if_not": []},
        {"name": "combo_phish_infra_cred_form", "score": 30, "label": "phishing infra redirect + credential form", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_infra_redirect", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_phish_infra_doc_lure", "score": 25, "label": "phishing infra redirect + doc sharing lure", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_infra_redirect", "doc_sharing_lure"], "if_any": [], "if_not": []},
        {"name": "combo_phish_infra_established", "score": 28, "label": "phishing infra redirect + domain >1yr", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_infra_redirect", "domain_gt_1yr"], "if_any": [], "if_not": []},
        {"name": "combo_phish_js_cred_form", "score": 25, "label": "phishing js behavior + credential form", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_js_behavior", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_phish_js_hijack_path", "score": 20, "label": "phishing js behavior + hijack path pattern", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_js_behavior", "hijack_path_pattern"], "if_any": [], "if_not": []},
        {"name": "combo_phish_js_shell_site", "score": 22, "label": "phishing js behavior + minimal shell", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_js_behavior", "minimal_shell"], "if_any": [], "if_not": []},
        {"name": "combo_phish_paths_cred_form", "score": 15, "label": "phishing paths + credential form", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_paths", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_phish_paths_new_30d", "score": 12, "label": "phishing paths + domain <30d", "category": "Phishing Infrastructure", "enabled": True, "if_all": ["phishing_paths", "domain_lt_30d"], "if_any": [], "if_not": []},

        # --- Phishing Lures (4 rules) ---
        {"name": "combo_doc_lure_cred_form", "score": 25, "label": "doc sharing lure + credential form", "category": "Phishing Lures", "enabled": True, "if_all": ["doc_sharing_lure", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_doc_lure_email_track", "score": 22, "label": "doc sharing lure + email tracking url", "category": "Phishing Lures", "enabled": True, "if_all": ["doc_sharing_lure", "email_tracking_url"], "if_any": [], "if_not": []},
        {"name": "combo_email_track_cred_form", "score": 28, "label": "email tracking url + credential form", "category": "Phishing Lures", "enabled": True, "if_all": ["email_tracking_url", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_email_track_doc_lure", "score": 22, "label": "email tracking url + doc sharing lure", "category": "Phishing Lures", "enabled": True, "if_all": ["email_tracking_url", "doc_sharing_lure"], "if_any": [], "if_not": []},

        # --- Phishing Templates (4 rules) ---
        {"name": "brand_keyword_phish", "score": 10, "label": "Brand + spoofing keyword domain without established legitimacy signals", "category": "Phishing Templates", "enabled": True, "if_all": ["brand_spoofing_keyword", "domain_brand_impersonation"], "if_any": [], "if_not": ["domain_gt_1yr", "app_store_high", "mx_enterprise"]},
        {"name": "phish_factory_template", "score": 10, "label": "Phishing factory template: mail.{domain} + no DKIM + weak DMARC + no PTR", "category": "Phishing Templates", "enabled": True, "if_all": ["mx_mail_prefix", "no_dkim", "dmarc_p_none", "no_ptr"], "if_any": [], "if_not": ["mx_enterprise", "has_bimi", "domain_gt_1yr"]},
        {"name": "platform_phish_setup", "score": 8, "label": "Free/platform hosting with self-hosted email and no DKIM", "category": "Phishing Templates", "enabled": True, "if_all": ["mx_selfhosted", "no_dkim"], "if_any": ["hosting_platform", "hosting_free"], "if_not": ["mx_enterprise", "app_store_high"]},
        {"name": "zero_email_auth", "score": 10, "label": "No email authentication at all on non-established domain", "category": "Phishing Templates", "enabled": True, "if_all": ["no_spf", "no_dkim", "no_dmarc"], "if_any": [], "if_not": ["domain_gt_1yr"]},

        # --- Positive Signals (3 rules) ---
        {"name": "combo_appstore_hi_bimi", "score": -8, "label": "app store high + has bimi", "category": "Positive Signals", "enabled": True, "if_all": ["app_store_high", "has_bimi"], "if_any": [], "if_not": []},
        {"name": "combo_appstore_hi_mta_sts", "score": -5, "label": "app store high + has mta sts", "category": "Positive Signals", "enabled": True, "if_all": ["app_store_high", "has_mta_sts"], "if_any": [], "if_not": []},
        {"name": "combo_appstore_med_bimi", "score": -5, "label": "app store medium + has bimi", "category": "Positive Signals", "enabled": True, "if_all": ["app_store_medium", "has_bimi"], "if_any": [], "if_not": []},

        # --- TLD Variant Spoofing (8 rules) ---
        {"name": "combo_tld_spoof_budget_host", "score": 12, "label": "tld variant spoofing + hosting budget shared", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "hosting_budget_shared"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_new_30d", "score": 25, "label": "tld variant spoofing + domain <30d", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_new_7d", "score": 30, "label": "tld variant spoofing + domain <7d", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "domain_lt_7d"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_no_dkim", "score": 15, "label": "tld variant spoofing + no dkim", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "no_dkim"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_no_trust", "score": 15, "label": "tld variant spoofing + missing trust signals", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "missing_trust_signals"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_parked", "score": 18, "label": "tld variant spoofing + parking page", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "parking_page"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_self_mx", "score": 15, "label": "tld variant spoofing + mx selfhosted", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "mx_selfhosted"], "if_any": [], "if_not": []},
        {"name": "combo_tld_spoof_shell_site", "score": 20, "label": "tld variant spoofing + minimal shell", "category": "TLD Variant Spoofing", "enabled": True, "if_all": ["tld_variant_spoofing", "minimal_shell"], "if_any": [], "if_not": []},

        # --- Tech Support Scam (10 rules) ---
        {"name": "combo_sus_prefix_cred_form", "score": 20, "label": "suspicious prefix + credential form", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_prefix", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_sus_prefix_new_30d", "score": 18, "label": "suspicious prefix + domain <30d", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_prefix", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_sus_prefix_sus_suffix", "score": 18, "label": "suspicious prefix + suspicious suffix", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_prefix", "suspicious_suffix"], "if_any": [], "if_not": []},
        {"name": "combo_sus_prefix_techsupport_tld", "score": 22, "label": "suspicious prefix + tech support tld", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_prefix", "tech_support_tld"], "if_any": [], "if_not": []},
        {"name": "combo_sus_suffix_cred_form", "score": 18, "label": "suspicious suffix + credential form", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_suffix", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_sus_suffix_new_30d", "score": 15, "label": "suspicious suffix + domain <30d", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_suffix", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_sus_suffix_techsupport_tld", "score": 20, "label": "suspicious suffix + tech support tld", "category": "Tech Support Scam", "enabled": True, "if_all": ["suspicious_suffix", "tech_support_tld"], "if_any": [], "if_not": []},
        {"name": "combo_techsupport_tld_cred_form", "score": 22, "label": "tech support tld + credential form", "category": "Tech Support Scam", "enabled": True, "if_all": ["tech_support_tld", "credential_form"], "if_any": [], "if_not": []},
        {"name": "combo_techsupport_tld_new_30d", "score": 18, "label": "tech support tld + domain <30d", "category": "Tech Support Scam", "enabled": True, "if_all": ["tech_support_tld", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "combo_techsupport_tld_no_https", "score": 15, "label": "tech support tld + no https", "category": "Tech Support Scam", "enabled": True, "if_all": ["tech_support_tld", "no_https"], "if_any": [], "if_not": []},

        # --- VirusTotal Combos (8 rules) ---
        {"name": "vt_malicious_brand", "score": 30, "label": "VT malicious + brand impersonation", "category": "VirusTotal", "enabled": True, "if_all": ["domain_brand_impersonation"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "vt_malicious_new_domain", "score": 25, "label": "VT malicious + domain <30d", "category": "VirusTotal", "enabled": True, "if_all": ["domain_lt_30d"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "vt_malicious_blacklisted", "score": 20, "label": "VT malicious + domain blacklisted", "category": "VirusTotal", "enabled": True, "if_all": ["domain_blacklisted"], "if_any": ["vt_malicious_high", "vt_malicious_medium"], "if_not": []},
        {"name": "vt_malicious_no_auth", "score": 20, "label": "VT malicious + no email auth", "category": "VirusTotal", "enabled": True, "if_all": ["no_dmarc", "no_spf"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "vt_malicious_cred_form", "score": 25, "label": "VT malicious + credential form", "category": "VirusTotal", "enabled": True, "if_all": ["credential_form"], "if_any": ["vt_malicious_high", "vt_malicious_medium"], "if_not": []},
        {"name": "vt_malicious_phishing_infra", "score": 30, "label": "VT malicious + phishing infra redirect", "category": "VirusTotal", "enabled": True, "if_all": ["phishing_infra_redirect"], "if_any": ["vt_malicious_high", "vt_malicious_medium"], "if_not": []},
        {"name": "vt_suspicious_new_domain", "score": 15, "label": "VT suspicious + domain <30d", "category": "VirusTotal", "enabled": True, "if_all": ["domain_lt_30d"], "if_any": ["vt_suspicious", "vt_suspicious_low"], "if_not": []},
        {"name": "vt_malicious_budget_host", "score": 18, "label": "VT malicious + budget hosting", "category": "VirusTotal", "enabled": True, "if_all": ["hosting_budget_shared"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},

        # --- Hacklink / SEO Spam Combos (7 rules) ---
        {"name": "hacklink_new_domain", "score": 25, "label": "hacklink detected + domain <30d", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_detected", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "hacklink_wp_compromised_budget", "score": 20, "label": "WP compromised + budget hosting", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_wp_compromised", "hosting_budget_shared"], "if_any": [], "if_not": []},
        {"name": "hacklink_blacklisted", "score": 20, "label": "hacklink + domain blacklisted", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_detected", "domain_blacklisted"], "if_any": [], "if_not": []},
        {"name": "hacklink_vt_malicious", "score": 30, "label": "hacklink + VT malicious — confirmed compromise", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_detected"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "hacklink_no_auth", "score": 18, "label": "hacklink + no email auth — domain may be abandoned", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_detected", "no_dmarc", "no_spf"], "if_any": [], "if_not": []},
        {"name": "hacklink_vulnerable_wp_new", "score": 22, "label": "vulnerable WP plugins + domain <90d", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_vulnerable_plugins", "domain_lt_90d"], "if_any": [], "if_not": []},
        {"name": "hacklink_spam_links_cloaking", "score": 20, "label": "spam links + 403 cloaking", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["hacklink_spam_links", "status_403_cloaking"], "if_any": [], "if_not": []},

        # --- Malicious Script / Hidden Injection (6 rules) ---
        {"name": "malicious_script_new_domain", "score": 30, "label": "malicious script + domain <30d — active drive-by", "category": "Malicious Script", "enabled": True, "if_all": ["malicious_script", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "malicious_script_vt_malicious", "score": 35, "label": "malicious script + VT malicious — confirmed compromise", "category": "Malicious Script", "enabled": True, "if_all": ["malicious_script"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "malicious_script_hacklink", "score": 30, "label": "malicious script + hacklink keywords — multi-vector compromise", "category": "Malicious Script", "enabled": True, "if_all": ["malicious_script", "hacklink_detected"], "if_any": [], "if_not": []},
        {"name": "hidden_injection_new_domain", "score": 25, "label": "hidden injection + domain <30d — injected from day one", "category": "Malicious Script", "enabled": True, "if_all": ["hidden_injection", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "hidden_injection_vt_malicious", "score": 30, "label": "hidden injection + VT malicious", "category": "Malicious Script", "enabled": True, "if_all": ["hidden_injection"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "hidden_injection_budget_host", "score": 20, "label": "hidden injection + budget hosting — mass-exploited shared host", "category": "Malicious Script", "enabled": True, "if_all": ["hidden_injection", "hosting_budget_shared"], "if_any": [], "if_not": []},

        # --- cPanel + Transfer Lock Combos (4 rules) ---
        {"name": "cpanel_transfer_lock_recent", "score": 22, "label": "cPanel + transfer lock recently added — post-compromise lockdown on shared hosting", "category": "Domain Takeover", "enabled": True, "if_all": ["cpanel_detected", "transfer_lock_recent"], "if_any": [], "if_not": []},
        {"name": "cpanel_whois_recently_updated", "score": 18, "label": "cPanel + WHOIS recently updated — possible recent compromise", "category": "Domain Takeover", "enabled": True, "if_all": ["cpanel_detected", "whois_recently_updated"], "if_any": [], "if_not": []},
        {"name": "cpanel_hacklink", "score": 20, "label": "cPanel + hacklink detected — classic hacklink campaign target", "category": "Domain Takeover", "enabled": True, "if_all": ["cpanel_detected", "hacklink_detected"], "if_any": [], "if_not": []},
        {"name": "cpanel_malicious_script", "score": 25, "label": "cPanel + malicious script — compromised shared hosting", "category": "Domain Takeover", "enabled": True, "if_all": ["cpanel_detected", "malicious_script"], "if_any": [], "if_not": []},

        # --- Transfer Lock Recently Added + Old Domain / VT Combos (4 rules) ---
        {"name": "transfer_lock_old_domain", "score": 0, "label": "transfer lock recently added + domain >1yr — post-compromise lockdown on established domain", "category": "Domain Takeover", "enabled": True, "if_all": ["transfer_lock_recent", "domain_gt_1yr"], "if_any": [], "if_not": []},
        {"name": "transfer_lock_whois_updated", "score": 0, "label": "transfer lock recently added + WHOIS recently updated — active post-compromise response", "category": "Domain Takeover", "enabled": True, "if_all": ["transfer_lock_recent", "whois_recently_updated"], "if_any": [], "if_not": []},
        {"name": "transfer_lock_vt_malicious", "score": 25, "label": "transfer lock recently added + VT malicious — locked down after threat intel flagged", "category": "Domain Takeover", "enabled": True, "if_all": ["transfer_lock_recent"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},
        {"name": "transfer_lock_hacklink", "score": 20, "label": "transfer lock recently added + hacklink — locked down after SEO injection found", "category": "Domain Takeover", "enabled": True, "if_all": ["transfer_lock_recent", "hacklink_detected"], "if_any": [], "if_not": []},

        # --- VT Malicious + Hacklink Keywords (cross-intel) ---
        {"name": "vt_malicious_hacklink_keywords", "score": 28, "label": "VT malicious + hacklink keywords — threat intel + content confirms compromise", "category": "VirusTotal", "enabled": True, "if_all": ["hacklink_keywords"], "if_any": ["vt_malicious_high", "vt_malicious_medium", "vt_malicious_low"], "if_not": []},

        # --- Empty Page Combos (3 rules) ---
        {"name": "empty_page_new_domain", "score": 18, "label": "empty page + domain <30d — parked/staged phishing domain", "category": "General Risk", "enabled": True, "if_all": ["empty_page", "domain_lt_30d"], "if_any": [], "if_not": []},
        {"name": "empty_page_no_auth", "score": 15, "label": "empty page + no email auth — abandoned/fraudulent domain", "category": "General Risk", "enabled": True, "if_all": ["empty_page", "no_spf", "no_dmarc"], "if_any": [], "if_not": []},
        {"name": "empty_page_transfer_lock_recent", "score": 18, "label": "empty page + transfer lock recently added — site gutted and locked after compromise", "category": "Domain Takeover", "enabled": True, "if_all": ["empty_page", "transfer_lock_recent"], "if_any": [], "if_not": []},

        # --- Cert Transparency Combos (3 rules) ---
        {"name": "ct_recent_old_domain", "score": 20, "label": "CT recent issuance + domain >1yr — possible domain takeover/reactivation", "category": "Domain Takeover", "enabled": True, "if_all": ["ct_recent_issuance", "domain_gt_1yr"], "if_any": [], "if_not": []},
        {"name": "ct_no_history_sending", "score": 15, "label": "no CT history + no email auth — ghost domain never used for web or email", "category": "General Risk", "enabled": True, "if_all": ["ct_no_history", "no_spf", "no_dmarc"], "if_any": [], "if_not": []},
        {"name": "ct_recent_hacklink", "score": 20, "label": "CT recent issuance + hacklink — newly activated compromised domain", "category": "Hacklink / SEO Spam", "enabled": True, "if_all": ["ct_recent_issuance", "hacklink_detected"], "if_any": [], "if_not": []},

    ],
    
    "suspicious_tlds": [
        '.xyz', '.top', '.work', '.click', '.link', '.info', '.biz', '.online',
        '.site', '.website', '.space', '.fun', '.icu', '.buzz', '.club',
        '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov',
        # Retail/e-commerce scam TLDs (cheap, frequently abused for fake stores)
        '.shop', '.store', '.sale', '.deals', '.bargains', '.discount', '.cheap',
        '.buy', '.shopping', '.market', '.boutique', '.fashion', '.shoes',
    ],
    
    "protected_brands": [
        'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
        'instagram', 'netflix', 'bankofamerica', 'chase', 'wellsfargo',
        'citibank', 'capitalone', 'americanexpress', 'amex', 'discover',
        'usps', 'fedex', 'ups', 'dhl', 'dropbox', 'docusign', 'adobe',
        'linkedin', 'twitter', 'whatsapp', 'telegram', 'snapchat', 'tiktok',
        'coinbase', 'binance', 'kraken', 'blockchain', 'metamask',
        'walmart', 'target', 'bestbuy', 'costco', 'homedepot', 'lowes',
        'ebay', 'alibaba', 'aliexpress', 'etsy', 'shopify', 'stripe',
        # Airlines (high-value phishing targets)
        'easyjet', 'ryanair', 'southwest', 'delta', 'united', 'jetblue',
        'lufthansa', 'emirates', 'qantas', 'wizzair',
        # Travel / Booking
        'booking', 'expedia', 'airbnb', 'tripadvisor',
        # Banks / Financial
        'hsbc', 'barclays', 'lloyds', 'natwest', 'santander',
        'monzo', 'revolut', 'venmo', 'cashapp', 'zelle', 'klarna',
        # Shipping / Logistics
        'royalmail', 'hermes', 'evri', 'dpd',
        # Telecoms
        'vodafone', 'tmobile', 'verizon', 'spectrum',
    ],
    
    "disposable_domains": [
        'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'mailinator.com',
        'maildrop.cc', 'throwaway.email', 'getnada.com', '10minutemail.com',
        'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com',
        'fakeinbox.com', 'trashmail.com', 'tempinbox.com',
    ],
    
    # ==========================================================================
    # BRAND IMPERSONATION TUNING (v5.x)
    # ==========================================================================
    # Controls how brand names are matched in domain names.
    #
    # short_brand_max_len: Brands with this many chars or fewer require word-
    #   boundary matching (hyphens, dots, start/end of domain part) to avoid
    #   substring false positives like "first" triggering "irs".
    #
    # brand_min_domain_ratio: Minimum ratio of brand length to domain-name
    #   length (excluding TLD). If the brand is too small a fraction of the
    #   domain, the match is ignored.  0.0 = disabled, 0.3 = brand must be
    #   at least 30% of the domain name.
    #
    # brand_allowlist_words: Common English words or legitimate business terms
    #   that happen to contain a short brand substring. If the domain name
    #   (normalized, without TLD) matches any of these, brand impersonation
    #   is NOT flagged. Checked via substring: if any allowlisted word is
    #   found spanning the brand match position, the match is suppressed.
    # ==========================================================================
    "brand_impersonation": {
        "short_brand_max_len": 5,
        "brand_min_domain_ratio": 0.25,
        "brand_allowlist_words": [
            # Words containing "irs" 
            "first", "stairs", "thirds", "birdsong", "hairspray", "thirst",
            "birthday", "affirm", "confirm", "firmware", "airshow", "fairshare",
            "chairside", "repairshop", "staircase",
            # Words containing "ups"
            "cups", "pups", "groups", "startups", "setups", "pickups", "lineups",
            "signups", "popups", "meetups", "roundups", "checkups", "backups",
            "mixups", "tups", "syrup", "disruption", "upscale", "upstream",
            "upset", "upside", "upsell",
            # Words containing "dhl" — rare in English but cover edge cases
            # Words containing "sky"
            "skyline", "skyscraper", "skylight", "whisky", "husky",
            # Words containing "cox"
            "coxswain",
            # Words containing "att"
            "attorney", "attic", "attitude", "attract", "attach", "attack",
            "attempt", "attend", "attention", "attribute", "matter", "battery",
            "pattern", "shatter", "scatter", "chatter", "flatter", "latter",
            "rattan", "cattle", "battle", "tatter", "hatter", "fatter",
            "batter", "chattel", "tattoo", "latte", "matte",
            # Words containing "avg" — rare naturally
            # Words containing "aol" — rare naturally
            # Words containing "hp" / "bt" / "ee" / "o2" — 2-char, skipped by len<3
            # Words containing "delta"
            "deltaforce",
            # Words containing "chase"
            "purchase", "purchaser",
            # Words containing "sage"
            "massage", "passage", "sagebrush", "message", "dosage", "usage",
            "visage", "corsage", "sausage",
            # Words containing "epic"
            "recipe", "epidem",
            # Words containing "canon"
            "canonical",
            # Words containing "steam"
            "downstream", "upstream", "mainstream", "steamboat",
            # Words containing "wise"
            "otherwise", "likewise", "clockwise", "stepwise", "enterprise",
            # Words containing "wish"
            "swish",
            # Words containing "zelle"
            "gazelle", "gazelles",
            # Words containing "three"
            # Words containing "apple"
            "pineapple", "appleseed", "grapple", "dapple", "snapple",
            # Words containing "venmo" — rare naturally
            # Words containing "ebay" — rare naturally
            # Words containing "etsy" — rare naturally
            # Words containing "dell"
            "model", "modell", "dwell", "dellay",
            # Words containing "klm" — rare naturally
            # Words containing "tsb" — rare naturally
            # Words containing "amex"
            "games", "gamer", "examex",
            # Words containing "evri" — rare naturally
            # Words containing "spirit"
            # "spirit" is 6 chars so covered by word boundary matching threshold
            # Generic safe patterns
            "digital", "solutions", "consulting", "services", "technology",
            "creative", "international", "professional", "management",
            "development", "foundation", "community", "education",
            "financial", "industrial", "commercial", "residential",
            "construction", "engineering", "healthcare", "marketing",
        ],
    },
    
    "domain_blacklists": [
        "dbl.spamhaus.org",
        "multi.surbl.org",
    ],
    
    "ip_blacklists": [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net",
    ],
    
    # ==========================================================================
    # BLOCKED ASN ORGANIZATIONS
    # ==========================================================================
    # Domains hosted on these ASN orgs get an instant high score (default: 100).
    # Match is case-insensitive substring against the ASN org name.
    # Use this for hosting providers you've confirmed are consistently used
    # by phishing/spam campaigns in your specific threat landscape.
    #
    # To find an ASN org name: run a domain through the analyzer and check
    # the hosting_asn_org field, or use "whois <IP>" / "dig TXT <IP>.origin.asn.cymru.com"
    #
    # Examples: "render" matches "Render" (AS397273)
    #           "frantech" matches "FranTech Solutions" (bulletproof host)
    #
    "blocked_asn_orgs": [
        # ASN org name substrings — case-insensitive match against hosting ASN org.
        # Instant DENY (100 points) when matched. Add your known-bad providers here.
        "render",           # AS397273 — Render.com, heavily abused for phishing infra
        # "frantech",       # AS53667 — BuyVM/Frantech, bulletproof-adjacent
        # "combahton",      # AS30823 — German bulletproof host
    ],
    "blocked_asn_org_score": 100,  # Score to apply when matched
    
    # ──────────────────────────────────────────────────────────────────
    # ALLOW LISTS — Domains cleared by admin review
    # ──────────────────────────────────────────────────────────────────
    # These lists suppress specific detection signals for domains that
    # have been manually reviewed and confirmed as legitimate.
    #
    # IMPORTANT: Adding a domain here does NOT reduce its score from
    # other signals — it only suppresses the specific signal category.
    # A domain on the spoofing allowlist still gets scored for email
    # auth gaps, blacklist hits, hosting risk, etc.
    #
    # Matching: exact domain match OR subdomain match (e.g., adding
    # "example.com" also covers "mail.example.com").
    # ──────────────────────────────────────────────────────────────────
    
    # Suppress TLD variant spoofing detection for these domains.
    # Use when a legitimate business operates on a non-.com TLD and
    # keeps triggering the variant check against the .com owner.
    # Example: terravision.eu is a real Italian transport company,
    # not spoofing terravision.com.
    "tld_variant_allowlist": [
        # "terravision.eu",
        # "facts.ae",
    ],
    
    # Suppress typosquat, brand impersonation, brand+keyword,
    # suspicious prefix, and suspicious suffix detection for these
    # domains. Use when a legitimate domain name pattern matches
    # a brand or keyword rule.
    # Example: cabonline.com triggers "suspicious suffix: online"
    # but is a legitimate Swedish taxi company.
    "spoofing_allowlist": [
        # "cabonline.com",
        # "gratuitpentrupc.com",
    ],
    
    "hosting_providers": {
        # =============================================================
        # BUDGET SHARED HOSTS (type: "budget_shared")
        # High spam/phishing rate due to cheap shared hosting plans
        # =============================================================
        "hostinger": {
            "name": "Hostinger",
            "type": "budget_shared",
            "ns_patterns": ["hostinger.com", "dns-parking.com"],
            "asn_numbers": [47583],
            "asn_org_patterns": ["hostinger"],
            "ptr_patterns": ["hostinger.com", "hostinger"],
        },
        "godaddy": {
            "name": "GoDaddy",
            "type": "budget_shared",
            "ns_patterns": ["domaincontrol.com"],
            "asn_numbers": [26496, 398101],
            "asn_org_patterns": ["godaddy", "go daddy"],
            "ptr_patterns": ["secureserver.net", "godaddy"],
        },
        "namecheap": {
            "name": "Namecheap",
            "type": "budget_shared",
            "ns_patterns": ["registrar-servers.com", "namecheaphosting.com"],
            "asn_numbers": [22612],
            "asn_org_patterns": ["namecheap"],
            "ptr_patterns": ["namecheap"],
        },
        "bluehost": {
            "name": "Bluehost",
            "type": "budget_shared",
            "ns_patterns": ["bluehost.com"],
            "asn_numbers": [11798],
            "asn_org_patterns": ["bluehost", "newfold digital"],
            "ptr_patterns": ["bluehost.com"],
        },
        "hostgator": {
            "name": "HostGator",
            "type": "budget_shared",
            "ns_patterns": ["hostgator.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["hostgator"],
            "ptr_patterns": ["hostgator.com"],
        },
        "ionos": {
            "name": "IONOS (1&1)",
            "type": "budget_shared",
            "ns_patterns": ["ui-dns.com", "ui-dns.de", "ui-dns.org", "ui-dns.biz"],
            "asn_numbers": [8560],
            "asn_org_patterns": ["ionos", "1&1", "1und1"],
            "ptr_patterns": ["ionos.com", "1and1.com", "kundenserver.de"],
        },
        "dreamhost": {
            "name": "DreamHost",
            "type": "budget_shared",
            "ns_patterns": ["dreamhost.com"],
            "asn_numbers": [26347],
            "asn_org_patterns": ["dreamhost"],
            "ptr_patterns": ["dreamhost.com"],
        },
        "siteground": {
            "name": "SiteGround",
            "type": "budget_shared",
            "ns_patterns": ["siteground.net", "sgvps.net"],
            "asn_numbers": [],
            "asn_org_patterns": ["siteground"],
            "ptr_patterns": ["siteground.net", "sgvps.net"],
        },
        "a2hosting": {
            "name": "A2 Hosting",
            "type": "budget_shared",
            "ns_patterns": ["a2hosting.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["a2 hosting"],
            "ptr_patterns": ["a2hosting.com"],
        },
        "ipage": {
            "name": "iPage",
            "type": "budget_shared",
            "ns_patterns": ["ipage.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["ipage"],
            "ptr_patterns": ["ipage.com"],
        },
        
        # =============================================================
        # FREE HOSTING (type: "free")
        # Very high spam/phishing rate - throwaway sites
        # =============================================================
        "000webhost": {
            "name": "000webhost",
            "type": "free",
            "ns_patterns": ["000webhost"],
            "asn_numbers": [],
            "asn_org_patterns": ["000webhost"],
            "ptr_patterns": ["000webhost"],
        },
        "infinityfree": {
            "name": "InfinityFree",
            "type": "free",
            "ns_patterns": ["byet.org", "byethost"],
            "asn_numbers": [],
            "asn_org_patterns": ["infinityfree", "byet"],
            "ptr_patterns": ["infinityfree", "byethost"],
        },
        "awardspace": {
            "name": "AwardSpace",
            "type": "free",
            "ns_patterns": ["awardspace.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["awardspace"],
            "ptr_patterns": ["awardspace.com"],
        },
        "freehosting": {
            "name": "FreeHosting.com",
            "type": "free",
            "ns_patterns": ["freehosting.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["freehosting"],
            "ptr_patterns": ["freehosting.com"],
        },
        "x10hosting": {
            "name": "x10Hosting",
            "type": "free",
            "ns_patterns": ["x10hosting.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["x10hosting"],
            "ptr_patterns": ["x10hosting.com"],
        },
        
        # =============================================================
        # SUSPECT / BULLETPROOF HOSTS (type: "suspect")
        # Known for tolerating abuse, used by cybercriminals
        # =============================================================
        "alexhost": {
            "name": "AlexHost (Moldova)",
            "type": "suspect",
            "ns_patterns": ["alexhost.md"],
            "asn_numbers": [200019],
            "asn_org_patterns": ["alexhost"],
            "ptr_patterns": ["alexhost"],
        },
        "yourserver": {
            "name": "YourServer.se",
            "type": "suspect",
            "ns_patterns": ["yourserver.se"],
            "asn_numbers": [],
            "asn_org_patterns": ["yourserver"],
            "ptr_patterns": ["yourserver"],
        },
        "privatelayer": {
            "name": "PrivateLayer",
            "type": "suspect",
            "ns_patterns": ["privatelayer.com"],
            "asn_numbers": [51852],
            "asn_org_patterns": ["privatelayer"],
            "ptr_patterns": ["privatelayer"],
        },
        "shinjiru": {
            "name": "Shinjiru",
            "type": "suspect",
            "ns_patterns": ["shinjiru.com.my"],
            "asn_numbers": [45839],
            "asn_org_patterns": ["shinjiru"],
            "ptr_patterns": ["shinjiru"],
        },
        "zservers": {
            "name": "Zservers",
            "type": "suspect",
            "ns_patterns": ["zservers.com"],
            "asn_numbers": [],
            "asn_org_patterns": ["zservers", "xhost"],
            "ptr_patterns": ["zservers"],
        },
        "stark_industries": {
            "name": "Stark Industries (PQ Hosting)",
            "type": "suspect",
            "ns_patterns": [],
            "asn_numbers": [44477, 213373],
            "asn_org_patterns": ["stark industries", "pq hosting"],
            "ptr_patterns": ["stark-industries", "pqhosting"],
        },
        "marosnet": {
            "name": "MAROSNET",
            "type": "suspect",
            "ns_patterns": [],
            "asn_numbers": [48166],
            "asn_org_patterns": ["marosnet"],
            "ptr_patterns": ["marosnet"],
        },
        "selectel_ru": {
            "name": "Selectel (Russia)",
            "type": "suspect",
            "ns_patterns": [],
            "asn_numbers": [49505],
            "asn_org_patterns": ["selectel"],
            "ptr_patterns": ["selectel.ru"],
        },
        "global_secure_layer": {
            "name": "Global Secure Layer",
            "type": "suspect",
            "ns_patterns": [],
            "asn_numbers": [398989],
            "asn_org_patterns": ["global secure layer"],
            "ptr_patterns": [],
        },
        "eliteteam": {
            "name": "ELITETEAM",
            "type": "suspect",
            "ns_patterns": [],
            "asn_numbers": [57523],
            "asn_org_patterns": ["eliteteam", "chang way"],
            "ptr_patterns": [],
        },
        "heymman": {
            "name": "Heymman Servers",
            "type": "suspect",
            "ns_patterns": [],
            "asn_numbers": [],
            "asn_org_patterns": ["heymman"],
            "ptr_patterns": ["heymman"],
        },
        
        # =============================================================
        # DEVELOPER PLATFORM HOSTING (type: "platform")
        # Legitimate dev platforms but heavily abused for phishing.
        # Free tiers allow rapid domain setup with HTTPS.
        # These platforms serve their OWN AASA/asset-links files for
        # all custom domains, causing false app-store-presence positives.
        # =============================================================
        "render": {
            "name": "Render",
            "type": "platform",
            "ns_patterns": [],
            "asn_numbers": [397273],
            "asn_org_patterns": ["render"],
            "ptr_patterns": ["onrender.com"],
            "known_ips": ["216.24.57.1"],
        },
        "netlify": {
            "name": "Netlify",
            "type": "platform",
            "ns_patterns": ["dns1.p01.nsone.net"],
            "asn_numbers": [395747],
            "asn_org_patterns": ["netlify"],
            "ptr_patterns": ["netlify"],
            "known_ips": [],
        },
        "vercel": {
            "name": "Vercel",
            "type": "platform",
            "ns_patterns": [],
            "asn_numbers": [209242],
            "asn_org_patterns": ["vercel"],
            "ptr_patterns": ["vercel"],
            "known_ips": ["76.76.21.21"],
        },
        "railway": {
            "name": "Railway",
            "type": "platform",
            "ns_patterns": [],
            "asn_numbers": [],
            "asn_org_patterns": ["railway"],
            "ptr_patterns": ["railway.app"],
            "known_ips": [],
        },
        "fly_io": {
            "name": "Fly.io",
            "type": "platform",
            "ns_patterns": [],
            "asn_numbers": [40509],
            "asn_org_patterns": ["fly.io"],
            "ptr_patterns": ["fly.dev"],
            "known_ips": [],
        },
    },
    
    # =================================================================
    # NAMESERVER RISK PATTERNS
    # Detect suspicious NS delegation independent of hosting provider.
    # Each list contains substrings matched against the FQDN of every
    # NS record (case-insensitive).  A single match fires the signal.
    # =================================================================
    "ns_risk_patterns": {
        # --- Parking / placeholder nameservers ---
        # Domain is parked, unused, or pending deletion.
        # A parked domain requesting sender approval is a strong red flag.
        "parking_ns": [
            "sedoparking.com",
            "parkingcrew.net",
            "above.com",
            "bodis.com",
            "parklogic.com",
            "pendingrenewaldeletion",
            "afternic.com",
            "hugedomains.com",
            "dan.com",
            "undeveloped.com",
            "domainparking",
            "parkeddomain",
            "dns-parking.com",       # Hostinger parking (before setup)
            "domainnameshop.com",    # Often seen on parked domains
            "expired-domain",
        ],
        
        # --- Dynamic DNS providers (authoritative NS) ---
        # Legitimate businesses never delegate their domain to dynamic
        # DNS services.  This is almost exclusively phishing/malware
        # infrastructure enabling rapid IP rotation.
        "dynamic_dns_ns": [
            "noip.com",
            "no-ip.com",
            "dyndns.org",
            "dyndns.com",
            "dynu.com",
            "changeip.com",
            "ddns.net",
            "duckdns.org",
            "freedns.afraid.org",
            "nsupdate.info",
            "dynv6.com",
            "spdyn.de",
            "dtdns.com",
            "tzo.com",
            "zoneedit.com",
            "dyn.com",               # Legacy DynDNS (now Oracle Dyn)
            "dnsdynamic.org",
            "3322.org",              # Chinese dynamic DNS, heavily abused
            "oray.com",              # Peanut shell dynamic DNS (China)
            "vicp.net",              # Oray dynamic DNS variant
        ],
        
        # --- Free / anonymous authoritative DNS providers ---
        # Minimal infrastructure investment.  Legitimate businesses
        # overwhelmingly use registrar NS, their host's NS, or a paid
        # service (Cloudflare, Route 53, DNSimple, etc.).
        "free_dns_ns": [
            "cloudns.net",           # Free tier authoritative DNS
            "desec.io",              # Free encrypted DNS
            "he.net",                # Hurricane Electric free DNS
            "porkbun.com",           # Free with registration (low signal)
            "luadns.com",            # Free tier
            "buddyns.com",           # Free secondary DNS
            "zilore.com",            # Free tier DNS
            "rage4.com",             # Free tier
            "1984hosting.com",       # Icelandic free DNS
        ],
    },
    
    "mx_providers": {
        "enterprise": {
            # Enterprise MX = strong legitimacy signal
            "patterns": [
                "google.com", "googlemail.com", "gmail-smtp",           # Google Workspace
                "outlook.com", "microsoft.com", "protection.outlook",   # Microsoft 365
                "pphosted.com", "proofpoint.com",                       # Proofpoint
                "mimecast.com",                                         # Mimecast
                "barracuda",                                            # Barracuda
                "messagelabs.com", "symantec",                          # Broadcom/Symantec
            ],
        },
        "standard": {
            # Legitimate but not enterprise-grade
            "patterns": [
                "zoho.com", "zohomail",                                 # Zoho
                "fastmail.com", "messagingengine",                      # Fastmail
                "icloud.com", "apple.com",                              # iCloud
                "yandex.ru", "yandex.net",                              # Yandex
                "ovh.net",                                              # OVH
                "emailsrvr.com", "rackspace",                           # Rackspace
                "secureserver.net",                                     # GoDaddy email
            ],
        },
        "disposable": {
            # Cheap/disposable MX - high risk signal
            "patterns": [
                "titan.email", "titanmail",                             # Titan (cheap, popular with spammers)
                "improvmx.com",                                         # ImprovMX (forwarding)
                "forwardemail.net",                                     # Forward Email
                "migadu.com",                                           # Migadu
                "mail-in-a-box",                                        # Self-hosted kit
                "pobox.com",                                            # Pobox forwarding
                "runbox.com",                                           # Runbox
                "mailfence.com",                                        # Mailfence
                "hostinger.com",                                        # Hostinger email
                "privateemail.com",                                     # Namecheap email
                "registrar-servers.com",                                # Namecheap default
                "ionos.com", "perfora.net",                             # IONOS
                "hover.com",                                            # Hover
                "dreamhost.com",                                        # DreamHost
            ],
        },
    },
}


def ensure_config_dir():
    """Ensure config directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    """Load configuration from file, or return defaults."""
    ensure_config_dir()
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded = json.load(f)
                # Merge with defaults to ensure all keys exist
                merged = copy.deepcopy(DEFAULT_CONFIG)
                merged.update(loaded)
                # Ensure nested dicts are merged properly
                if 'weights' in loaded:
                    default_weights = copy.deepcopy(DEFAULT_CONFIG.get('weights', {}))
                    merged['weights'] = {**default_weights, **loaded['weights']}
                    
                    # Rename migration: transfer_lock_missing → transfer_lock_recent
                    if 'transfer_lock_missing' in merged['weights'] and 'transfer_lock_recent' not in loaded.get('weights', {}):
                        merged['weights']['transfer_lock_recent'] = merged['weights'].pop('transfer_lock_missing')
                    elif 'transfer_lock_missing' in merged['weights']:
                        merged['weights'].pop('transfer_lock_missing', None)
                    
                    # Migrate rules referencing the old signal name
                    if 'rules' in loaded:
                        for rule in loaded['rules']:
                            for key in ('if_all', 'if_any', 'if_not'):
                                if key in rule:
                                    rule[key] = ['transfer_lock_recent' if s == 'transfer_lock_missing' else s for s in rule[key]]
                    
                    # v7.1 weight migration: if saved config has old (lower) weights for
                    # signals that were bumped in v7.1, upgrade them to new defaults.
                    # Only applies if user hasn't explicitly customized them above the old defaults.
                    saved_version = loaded.get('config_version', '0')
                    if saved_version < '7.1':
                        v71_bumps = {
                            # signal: (old_default, new_default) — only upgrade if saved == old
                            'malicious_script': (40, 65),
                            'hidden_injection': (35, 55),
                            'hacklink_detected': (35, 50),
                            'hacklink_wp_compromised': (30, 45),
                            'hacklink_spam_links': (25, 35),
                            'hacklink_vulnerable_plugins': (20, 25),
                            'hacklink_keywords': (12, 15),
                            'vt_malicious_high': (45, 65),
                            'vt_malicious_medium': (30, 40),
                            'vt_malicious_low': (18, 22),
                            'vt_suspicious': (12, 15),
                            'empty_page': (15, 20),
                            'transfer_lock_recent': (12, 15),
                            'ct_no_history': (12, 15),
                            'whois_recently_updated': (8, 10),
                            'ct_recent_issuance': (8, 10),
                            'cpanel_detected': (6, 8),
                        }
                        for signal, (old_val, new_val) in v71_bumps.items():
                            saved_val = loaded['weights'].get(signal, old_val)
                            if saved_val <= old_val:  # User hasn't bumped it above old default
                                merged['weights'][signal] = new_val
                        merged['config_version'] = '7.1'
                    
                    # v7.2 migration: malicious_script raised to 100 (instant deny for HIGH
                    # confidence), new malicious_script_medium signal added at 25 for MEDIUM.
                    if saved_version < '7.2':
                        v72_bumps = {
                            'malicious_script': (65, 100),
                            'hidden_injection': (55, 100),
                            'hacklink_detected': (50, 100),
                        }
                        for signal, (old_val, new_val) in v72_bumps.items():
                            saved_val = loaded['weights'].get(signal, old_val)
                            if saved_val <= old_val:
                                merged['weights'][signal] = new_val
                        # Ensure new signal exists
                        if 'malicious_script_medium' not in merged['weights']:
                            merged['weights']['malicious_script_medium'] = 25
                        merged['config_version'] = '7.2'
                # Legacy: if old config has combos, ignore them (now in rules)
                loaded.pop('combos', None)
                loaded.pop('disabled_combos', None)
                # Rules: merge by name (user rules override defaults with same name,
                # new user rules are added). Set "rules_replace": true in config.json
                # to completely replace defaults instead of merging.
                if 'rules' in loaded:
                    if loaded.get('rules_replace', False):
                        # Full replacement mode
                        merged['rules'] = loaded['rules']
                    else:
                        # Merge mode: start with deep copy of defaults, override by name, add new
                        default_rules = {r['name']: copy.deepcopy(r) for r in DEFAULT_CONFIG.get('rules', []) if 'name' in r}
                        for user_rule in loaded['rules']:
                            name = user_rule.get('name', '')
                            if name:
                                default_rules[name] = user_rule  # Override or add
                            else:
                                default_rules[f"_unnamed_{id(user_rule)}"] = user_rule
                        merged['rules'] = list(default_rules.values())
                return merged
        except Exception as e:
            print(f"Error loading config: {e}")
    
    return copy.deepcopy(DEFAULT_CONFIG)


def save_config(config: dict) -> bool:
    """Save configuration to file."""
    ensure_config_dir()
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, indent=2, fp=f)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def get_weight(config: dict, signal: str) -> int:
    """Get weight for a signal from config."""
    return config.get('weights', {}).get(signal, DEFAULT_CONFIG['weights'].get(signal, 0))


def get_combo_weight(config: dict, signal1: str, signal2: str) -> int:
    """DEPRECATED: Combos are now unified rules. Returns 0."""
    return 0
