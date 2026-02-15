"""
Configuration management for Domain Sender Approval
"""

import json
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
    
    "weights": {
        # === FRAUD/PHISHING SIGNALS (High weights - these SHOULD trigger DENY) ===
        "domain_blacklisted": 45,
        "ip_blacklisted": 40,
        "typosquat_detected": 40,
        "brand_impersonation": 35,
        "malware_links": 50,
        "disposable_email": 40,
        "spf_pass_all": 40,           # +all allows anyone to spoof - security risk
        "domain_lt_7d": 35,           # Brand new domain - high risk
        "credential_form": 12,        # Only concerning if combined with other signals
        "sensitive_fields": 10,
        
        # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
        "suspicious_prefix": 15,           # app-, my-, support-, login-, etc.
        "suspicious_suffix": 15,           # account, setup, cancellation, etc.
        "tech_support_tld": 20,            # .support, .tech, .help, etc.
        "domain_brand_impersonation": 28,  # Brand name IN domain (app-spectrum.com)
        
        # === TLD VARIANT SPOOFING DETECTION ===
        "tld_variant_spoofing": 30,        # Signup domain is TLD variant of established business
        
        # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
        "hijack_path_pattern": 12,         # /tunnel/, /bid/, /secure/ paths
        "doc_sharing_lure": 15,            # "Secure Document Sharing" content
        "phishing_js_behavior": 18,        # atob(), hash extraction, etc.
        "phishing_infra_redirect": 25,     # Redirect to workers.dev, etc.
        "email_tracking_url": 20,          # Email in URL hash (tracking)
        
        # === E-COMMERCE / RETAIL SCAM INDICATORS ===
        "retail_scam_tld": 12,             # .shop, .store, .sale, etc.
        "ecommerce_no_identity": 15,       # E-commerce site with no business identity
        "cross_domain_brand_link": 18,     # Links to same-brand different TLD (clone indicator)
        "ecommerce_missing_policies": 8,   # E-commerce without terms/refund policy
        
        # === DELIVERABILITY CONCERNS (Low weights - warn but don't deny alone) ===
        "no_spf": 8,                  # Missing SPF - their problem, not fraud
        "spf_neutral_all": 5,         # ?all - weak but not dangerous
        "spf_softfail_all": 2,        # ~all - totally acceptable, very minor
        "spf_too_many_lookups": 4,
        "spf_syntax_error": 6,
        "no_dmarc": 10,               # Missing DMARC - deliverability issue only
        "dmarc_p_none": 8,            # p=none - tells receivers to do nothing about failures (raised from 5)
        "dmarc_no_rua": 2,            # No reporting - trivial
        "dmarc_syntax_error": 4,
        "no_dkim": 10,                # Missing DKIM - strong risk signal per disabled apps data (raised from 6)
        "no_mx": 8,                   # No MX - can't receive bounces
        "null_mx": 12,
        "mx_free_provider": 6,
        
        # === INFRASTRUCTURE CONCERNS (Low weights) ===
        "no_ptr": 4,                  # Missing PTR - minor
        "ptr_mismatch": 5,
        "no_https": 8,                # No HTTPS - minor concern
        "tls_handshake_failed": 20,   # SSL handshake fails (cipher/protocol mismatch)  # v4.4
        "tls_connection_failed": 8,   # Can't reach port 443 (no HTTPS service)          # v4.4
        "http_accessible": 2,
        "cert_self_signed": 6,
        "cert_expired": 8,
        "cert_wrong_host": 8,
        
        # === DOMAIN AGE (Moderate for very new, low otherwise) ===
        "domain_lt_30d": 10,          # 7-30 days old - moderate concern
        "domain_lt_90d": 4,           # 30-90 days old - minor concern
        "suspicious_tld": 6,          # High-abuse TLD
        "free_email_domain": 12,      # Sending from gmail.com etc
        "free_hosting": 6,
        "url_shortener": 8,
        
        # === REDIRECT/CLOAKING CONCERNS ===
        "redirect_chain_2plus": 6,
        "redirect_chain_3plus": 4,
        "redirect_cross_domain": 8,
        "redirect_temp_302_307": 6,
        
        # === SUSPICIOUS BEHAVIOR (Higher weights - actual red flags) ===
        "status_401_unauthorized": 12,    # 401 on public site - unusual
        "status_403_cloaking": 15,
        "status_429_throttling": 8,
        "status_503_disposable": 8,
        "status_5xx_errors": 4,
        "access_restricted": 10,          # 401 or 403 on what should be public domain
        "minimal_shell": 10,
        "js_redirect": 8,
        "meta_refresh": 5,
        "external_js_loader": 6,
        "obfuscated_js": 10,
        "phishing_paths": 15,
        "form_posts_external": 10,
        "suspicious_iframe": 8,
        "parking_page": 6,
        
        # === CORPORATE TRUST SIGNALS (Missing signals indicate opaque entity) ===
        "missing_trust_signals": 8,       # No about/contact/privacy pages
        "opaque_entity": 20,              # Access blocked + no trust signals = high risk
        
        # === BONUSES (Reduce score) ===
        "has_bimi": -10,
        "has_mta_sts": -6,
        
        # === APP STORE PRESENCE BONUSES (Legitimacy signal) ===
        # Rare for bad actors to maintain real app store presence
        "app_store_high": -15,    # Verified deep links (AASA/assetlinks) or multiple signals
        "app_store_medium": -5,   # Page links to app stores or iTunes API match (reduced - easy to fake)
        "app_store_low": 0,       # Keyword-only match in iTunes (disabled - too weak, 66% of disabled apps had this)
        
        # === HOSTING PROVIDER PENALTIES ===
        # Budget shared hosts and free hosts have higher spam/phishing rates
        "hosting_budget_shared": 8,   # Hostinger, GoDaddy shared, Namecheap shared, etc.
        "hosting_free": 12,           # 000webhost, InfinityFree, AwardSpace, etc.
        "hosting_suspect": 18,        # Known bulletproof / abuse-tolerant hosts
        
        # === MX PROVIDER SCORING (v4.7) ===
        "mx_disposable": 10,          # Disposable/cheap MX (Titan, ImprovMX, Hostinger email, etc.)
        "mx_selfhosted": 6,           # Self-hosted MX on same domain/IP - no provider oversight
        "mx_enterprise_bonus": -5,    # Enterprise MX (Google Workspace, M365, Proofpoint) = legitimacy signal
    },
    
    "combos": {
        # === CRITICAL PHISHING INFRASTRUCTURE COMBOS (from research) ===
        # These detect infrastructure intent, not just content
        
        # New domain + redirect chain = HIGH (attackers register, redirect, abandon)
        "domain_lt_7d+redirect_chain_2plus": 20,
        "domain_lt_7d+redirect_temp_302_307": 18,
        "domain_lt_30d+redirect_chain_2plus": 12,
        "domain_lt_30d+redirect_temp_302_307": 10,
        
        # 403 cloaking + new domain = VERY HIGH (scanner blocking on fresh domain)
        "status_403_cloaking+domain_lt_7d": 25,
        "status_403_cloaking+domain_lt_30d": 15,
        "status_403_cloaking+credential_form": 20,
        
        # No HTTPS + redirect = CRITICAL (cheap disposable infrastructure)
        "no_https+redirect_chain_2plus": 18,
        "no_https+redirect_temp_302_307": 15,
        "no_https+redirect_cross_domain": 15,
        
        # 503 + new domain = HIGH (disposable/bulletproof hosting)
        "status_503_disposable+domain_lt_7d": 18,
        "status_503_disposable+domain_lt_30d": 12,
        
        # 429 throttling + new domain = MEDIUM-HIGH (selective exposure)
        "status_429_throttling+domain_lt_30d": 10,
        
        # === ERROR RESPONSE CODE COMBOS (from predictive model research) ===
        # "Response codes become very powerful when combined with infrastructure signals"
        # "Most real phishing campaigns trigger 2-3 of these simultaneously"
        
        # --- 403 Cloaking + Redirect Combos (Very High) ---
        # Doc: "403 blocking + redirect = strong cloaking / anti-analysis"
        "status_403_cloaking+redirect_chain_2plus": 22,
        "status_403_cloaking+redirect_temp_302_307": 22,
        "status_403_cloaking+redirect_cross_domain": 20,
        
        # --- 403 Cloaking + No HTTPS Combo (High) ---
        # Doc: Cheap disposable infra that also blocks scanners
        "status_403_cloaking+no_https": 18,
        
        # --- 403 Cloaking + Content/Cloaking Combos (Very High) ---
        # Doc: "200 loader shell + JS redirect = Very high" — same logic for 403
        "status_403_cloaking+minimal_shell": 22,
        "status_403_cloaking+js_redirect": 20,
        "status_403_cloaking+phishing_paths": 22,
        "status_403_cloaking+brand_impersonation": 25,
        
        # --- 429 Throttling + Redirect/Content Combos (Medium-High) ---
        # Doc: "Indicates selective exposure infrastructure"
        "status_429_throttling+domain_lt_7d": 15,
        "status_429_throttling+redirect_chain_2plus": 12,
        "status_429_throttling+redirect_temp_302_307": 12,
        "status_429_throttling+credential_form": 15,
        "status_429_throttling+no_https": 12,
        "status_429_throttling+minimal_shell": 15,
        
        # --- 503 Disposable + Redirect/Content Combos (High) ---
        # Doc: "Disposable phishing servers frequently unstable"
        "status_503_disposable+redirect_chain_2plus": 15,
        "status_503_disposable+redirect_temp_302_307": 15,
        "status_503_disposable+redirect_cross_domain": 15,
        "status_503_disposable+no_https": 15,
        "status_503_disposable+credential_form": 18,
        "status_503_disposable+minimal_shell": 15,
        
        # --- 401 Unauthorized + Infrastructure Combos (High) ---
        # Doc: "401 on public-facing domain = unusual"
        "status_401_unauthorized+domain_lt_7d": 18,
        "status_401_unauthorized+domain_lt_30d": 12,
        "status_401_unauthorized+no_https": 15,
        "status_401_unauthorized+redirect_chain_2plus": 15,
        "status_401_unauthorized+redirect_temp_302_307": 12,
        "status_401_unauthorized+credential_form": 18,
        "status_401_unauthorized+minimal_shell": 15,
        
        # --- Error Code Cross-Combos (High) ---
        # Doc: "Most real phishing campaigns trigger 2-3 simultaneously"
        "status_403_cloaking+status_503_disposable": 18,
        "status_403_cloaking+status_429_throttling": 15,
        "status_401_unauthorized+status_403_cloaking": 18,
        "status_401_unauthorized+status_503_disposable": 15,
        "status_429_throttling+status_503_disposable": 12,
        
        # --- Error Codes + Hijacked Domain Indicators (Very High) ---
        # Established domain showing error codes + phishing infra = compromised
        "status_403_cloaking+hijack_path_pattern": 22,
        "status_403_cloaking+doc_sharing_lure": 20,
        "status_403_cloaking+phishing_js_behavior": 22,
        "status_403_cloaking+phishing_infra_redirect": 28,
        "status_503_disposable+hijack_path_pattern": 15,
        "status_503_disposable+phishing_infra_redirect": 22,
        
        # === OPAQUE ENTITY / SUPPLIER FRAUD COMBOS ===
        # Access restricted + missing trust signals = potential B2B fraud vector
        "opaque_entity+domain_lt_30d": 25,           # New + opaque = very high risk
        "opaque_entity+domain_lt_90d": 18,           # Newer + opaque = high risk
        "access_restricted+missing_trust_signals": 15,  # Can't verify entity
        "access_restricted+domain_lt_30d": 15,       # New domain that blocks access
        "missing_trust_signals+domain_lt_30d": 12,   # New domain with no corporate footprint
        
        # === TECH SUPPORT SCAM PATTERN COMBOS ===
        # Domain name patterns (app-brand.com, brandaccount.com) + other signals
        
        # TLD variant spoofing combos — amplify when combined with other spoof signals
        "tld_variant_spoofing+domain_lt_30d": 25,           # New domain + TLD variant = very high
        "tld_variant_spoofing+domain_lt_7d": 30,            # Brand new + TLD variant = near certain
        "tld_variant_spoofing+minimal_shell": 20,           # Hollow page + TLD variant
        "tld_variant_spoofing+no_dkim": 15,                 # No email auth + TLD variant
        "tld_variant_spoofing+parking_page": 18,            # Parking page + TLD variant
        "tld_variant_spoofing+missing_trust_signals": 15,   # No corporate pages + TLD variant
        "tld_variant_spoofing+hosting_budget_shared": 12,   # Budget host + TLD variant
        "tld_variant_spoofing+mx_selfhosted": 15,            # Self-hosted MX + TLD variant
        
        # Brand impersonation in domain name = VERY HIGH risk combos
        "domain_brand_impersonation+credential_form": 30,
        "domain_brand_impersonation+domain_lt_30d": 25,
        "domain_brand_impersonation+suspicious_prefix": 20,
        "domain_brand_impersonation+suspicious_suffix": 20,
        "domain_brand_impersonation+tech_support_tld": 25,
        "domain_brand_impersonation+no_https": 18,
        
        # Suspicious prefix (app-, support-, etc.) combos
        "suspicious_prefix+domain_lt_30d": 18,
        "suspicious_prefix+credential_form": 20,
        "suspicious_prefix+tech_support_tld": 22,
        "suspicious_prefix+suspicious_suffix": 18,
        
        # Suspicious suffix (account, setup, etc.) combos
        "suspicious_suffix+domain_lt_30d": 15,
        "suspicious_suffix+credential_form": 18,
        "suspicious_suffix+tech_support_tld": 20,
        
        # Tech support scam TLD combos
        "tech_support_tld+domain_lt_30d": 18,
        "tech_support_tld+credential_form": 22,
        "tech_support_tld+no_https": 15,
        
        # === HIJACKED DOMAIN / STEPPING STONE COMBOS ===
        # Key insight: Old established domains with phishing content = hijacked
        
        # Phishing infrastructure redirect combos (workers.dev, etc.)
        "phishing_infra_redirect+credential_form": 30,
        "phishing_infra_redirect+doc_sharing_lure": 25,
        "phishing_infra_redirect+domain_gt_1yr": 28,  # Old domain redirecting to phishing infra
        
        # Document sharing lure combos
        "doc_sharing_lure+credential_form": 25,
        "doc_sharing_lure+hijack_path_pattern": 22,
        "doc_sharing_lure+phishing_js_behavior": 25,
        "doc_sharing_lure+email_tracking_url": 22,
        
        # Email tracking in URL combos
        "email_tracking_url+credential_form": 28,
        "email_tracking_url+doc_sharing_lure": 22,
        "email_tracking_url+phishing_js_behavior": 25,
        
        # Phishing JS behavior combos
        "phishing_js_behavior+credential_form": 25,
        "phishing_js_behavior+hijack_path_pattern": 20,
        "phishing_js_behavior+minimal_shell": 22,
        
        # Hijack path pattern combos
        "hijack_path_pattern+credential_form": 20,
        "hijack_path_pattern+domain_gt_1yr": 18,  # Established domain with suspicious path
        
        # Minimal shell + JS redirect = VERY HIGH (classic phishing cloaking)
        "minimal_shell+js_redirect": 18,
        "minimal_shell+domain_lt_30d": 12,
        "minimal_shell+credential_form": 15,
        
        # Cross-domain redirect + new domain = HIGH
        "redirect_cross_domain+domain_lt_7d": 18,
        "redirect_cross_domain+domain_lt_30d": 12,
        
        # === FRAUD/BRAND ABUSE COMBOS ===
        "typosquat_detected+credential_form": 35,
        "typosquat_detected+domain_lt_30d": 28,
        "typosquat_detected+redirect_chain_2plus": 25,
        "brand_impersonation+credential_form": 35,
        "brand_impersonation+domain_lt_30d": 22,
        "brand_impersonation+no_https": 20,
        "domain_blacklisted+domain_lt_30d": 30,
        
        # === DELIVERABILITY COMBOS (lower penalties) ===
        "no_spf+no_dmarc": 4,
        "spf_pass_all+no_dmarc": 15,
        "no_dkim+no_dmarc": 3,
        "no_spf+no_dkim": 3,
        "no_spf+domain_lt_30d": 5,
        "no_dmarc+domain_lt_30d": 5,
        "no_dkim+domain_lt_30d": 4,
        "no_spf+domain_lt_7d": 10,
        "no_dmarc+domain_lt_7d": 10,
        "no_mx+domain_lt_30d": 6,
        
        # === OTHER SUSPICIOUS COMBOS ===
        "credential_form+no_https": 12,
        "phishing_paths+credential_form": 15,
        "phishing_paths+domain_lt_30d": 12,
        "free_email_domain+credential_form": 10,
        "disposable_email+no_spf": 8,
        "disposable_email+domain_lt_30d": 18,
        "no_ptr+domain_lt_30d": 4,
        "ptr_mismatch+domain_blacklisted": 10,
        "suspicious_tld+domain_lt_30d": 10,
        "suspicious_tld+redirect_chain_2plus": 10,
        
        # === APP STORE PRESENCE COMBOS (Legitimacy mitigation) ===
        # App presence + strong email auth = very likely legitimate sender
        "app_store_high+has_bimi": -8,              # Verified app + BIMI = strong legitimacy
        "app_store_high+has_mta_sts": -5,           # Verified app + MTA-STS = security-conscious
        "app_store_medium+has_bimi": -5,             # Moderate app presence + BIMI
        
        # === HOSTING PROVIDER COMBOS ===
        # Budget/free hosting + other red flags = amplified risk
        "hosting_budget_shared+domain_lt_30d": 12,       # New domain on cheap host
        "hosting_budget_shared+domain_lt_7d": 18,        # Brand new domain on cheap host
        "hosting_budget_shared+no_spf": 6,               # Cheap host + no email auth
        "hosting_budget_shared+no_dmarc": 6,             # Cheap host + no DMARC
        "hosting_budget_shared+credential_form": 15,     # Cheap host + login form
        "hosting_budget_shared+brand_impersonation": 18, # Cheap host + brand abuse
        "hosting_free+domain_lt_30d": 15,                # New domain on free host
        "hosting_free+credential_form": 18,              # Free host + login form
        "hosting_free+brand_impersonation": 22,          # Free host + brand abuse
        "hosting_suspect+domain_lt_30d": 22,             # Suspect host + new domain
        "hosting_suspect+domain_lt_7d": 28,              # Suspect host + brand new
        "hosting_suspect+credential_form": 25,           # Suspect host + login form
        "hosting_suspect+brand_impersonation": 28,       # Suspect host + brand abuse
        "hosting_suspect+no_https": 18,                  # Suspect host + no HTTPS
        
        # === WEAK AUTH COMBOS (v4.7 - from disabled apps analysis) ===
        "no_dkim+dmarc_p_none": 8,                   # No DKIM + permissive DMARC - 84% of disabled apps had this
        "no_dkim+dmarc_p_none+spf_softfail_all": 6,  # Triple weak auth - most common bad actor profile (+6 additional)
        "hosting_budget_shared+no_dkim": 6,           # Budget host + no DKIM - high risk combo
        
        # === MX PROVIDER COMBOS (v4.7) ===
        "mx_disposable+no_dkim": 8,                      # Disposable MX + no DKIM
        "mx_disposable+dmarc_p_none": 6,                 # Disposable MX + permissive DMARC
        "mx_disposable+hosting_budget_shared": 8,        # Disposable MX + budget host
        "mx_selfhosted+no_dkim": 6,                      # Self-hosted MX + no DKIM
        "mx_selfhosted+hosting_budget_shared": 6,        # Self-hosted MX + budget host
        
        # === PHISHING MAIL TEMPLATE COMBOS (v5.1 - from Swedish invoice phish analysis) ===
        # Cookie-cutter phishing infrastructure: mail.{domain} + no DKIM + DMARC p=none + no PTR
        "mx_mail_prefix+no_dkim": 5,                     # mail.{domain} template + no DKIM
        "mx_mail_prefix+no_ptr": 4,                      # mail.{domain} template + no reverse DNS
        "mx_mail_prefix+no_dkim+dmarc_p_none": 8,        # Triple: phishing mail server template
        "mx_mail_prefix+no_dkim+dmarc_p_none+no_ptr": 10,  # FULL phishing template fingerprint
        "spf_no_external_includes+mx_selfhosted": 5,     # No real email provider anywhere
        "spf_no_external_includes+mx_mail_prefix": 5,    # Self-only SPF + mail.{domain} template
        
        # === PLATFORM HOSTING COMBOS (v5.1) ===
        # Dev platforms (Render, Netlify, Vercel) with self-hosted email = phishing setup
        "hosting_platform+mx_selfhosted": 6,             # Platform hosting + self-hosted MX
        "hosting_platform+mx_mail_prefix": 8,            # Platform hosting + mail.{domain} template
        "hosting_platform+no_dkim": 5,                   # Platform hosting + no DKIM
        "hosting_platform+mx_selfhosted+no_dkim": 10,   # Platform + self MX + no DKIM
    },
    
    # ==========================================================================
    # CUSTOM RULES ENGINE
    # ==========================================================================
    # Rules provide if/then logic beyond simple combos. Each rule can use:
    #
    #   if_all:  ALL signals must be present (AND logic)
    #   if_any:  AT LEAST ONE signal must be present (OR logic)
    #   if_not:  NONE of these signals may be present (exclusion)
    #   score:   points to add (positive = riskier, negative = safer)
    #   name:    unique identifier (shown in output)
    #   label:   human-readable description (shown in ISSUES when triggered)
    #
    # HOW IT WORKS:
    #   1. if_all is checked first — ALL must match (skip rule if any missing)
    #   2. if_any is checked next — AT LEAST ONE must match (skip if none match)
    #   3. if_not is checked last — NONE may be present (skip if any found)
    #   4. If all conditions pass, the rule fires and score is applied
    #
    # AVAILABLE SIGNALS (use in if_all, if_any, if_not):
    #   Email auth:     no_spf, no_dkim, no_dmarc, spf_pass_all, spf_softfail_all,
    #                   spf_neutral_all, dmarc_p_none, dmarc_no_rua,
    #                   spf_no_external_includes
    #   MX:             no_mx, null_mx, mx_enterprise, mx_disposable, mx_selfhosted,
    #                   mx_mail_prefix
    #   DNS:            no_ptr, ptr_mismatch
    #   Trust:          has_bimi, has_mta_sts
    #   App store:      app_store_high, app_store_medium, app_store_low,
    #                   app_store_platform_false_positive
    #   Blacklists:     domain_blacklisted, ip_blacklisted
    #   Domain age:     domain_lt_7d, domain_lt_30d, domain_lt_90d, domain_gt_1yr
    #   Domain type:    suspicious_tld, free_email_domain, disposable_email,
    #                   typosquat_detected, free_hosting
    #   Hosting:        hosting_budget_shared, hosting_free, hosting_suspect,
    #                   hosting_platform
    #   Domain name:    suspicious_prefix, suspicious_suffix, is_tech_support_tld,
    #                   domain_brand_impersonation
    #   TLD variant:    tld_variant_spoofing
    #   Web:            no_https, tls_handshake_failed, tls_connection_failed,
    #                   cert_expired, cert_self_signed
    #   Redirects:      redirect_chain_2plus, redirect_cross_domain, redirect_temp_302_307
    #   Status codes:   status_401_unauthorized, status_403_cloaking,
    #                   status_429_throttling, status_503_disposable
    #   Content:        minimal_shell, js_redirect, meta_refresh, has_external_js,
    #                   missing_trust_signals, access_restricted, opaque_entity
    #   Scam patterns:  hijack_path_pattern, doc_sharing_lure, phishing_js_behavior,
    #                   phishing_infra_redirect, email_tracking_url
    #   E-commerce:     retail_scam_tld, cross_domain_brand_link, ecommerce_no_identity
    #
    # EXAMPLES:
    #
    #   "Phishing mail template but NOT on a known enterprise MX"
    #   {
    #       "name": "phish_mail_no_enterprise",
    #       "if_all": ["mx_mail_prefix", "no_dkim", "dmarc_p_none"],
    #       "if_not": ["mx_enterprise", "has_bimi"],
    #       "score": 15,
    #       "label": "Phishing mail server template without enterprise email"
    #   }
    #
    #   "New domain on ANY cheap/free hosting"
    #   {
    #       "name": "new_domain_cheap_host",
    #       "if_all": ["domain_lt_30d"],
    #       "if_any": ["hosting_budget_shared", "hosting_free", "hosting_platform"],
    #       "score": 12,
    #       "label": "New domain on cheap/free hosting"
    #   }
    #
    #   "Established domain with good auth gets a bonus"
    #   {
    #       "name": "established_good_auth",
    #       "if_all": ["domain_gt_1yr", "has_bimi"],
    #       "if_not": ["no_dkim", "no_dmarc", "no_spf"],
    #       "score": -10,
    #       "label": "Established domain with full email authentication"
    #   }
    #
    "rules": [
        # --- Built-in rules (demonstrating the engine) ---
        {
            "name": "phish_factory_template",
            "if_all": ["mx_mail_prefix", "no_dkim", "dmarc_p_none", "no_ptr"],
            "if_not": ["mx_enterprise", "has_bimi", "domain_gt_1yr"],
            "score": 10,
            "label": "Phishing factory template: mail.{domain} + no DKIM + weak DMARC + no PTR"
        },
        {
            "name": "platform_phish_setup",
            "if_all": ["mx_selfhosted", "no_dkim"],
            "if_any": ["hosting_platform", "hosting_free"],
            "if_not": ["mx_enterprise", "app_store_high"],
            "score": 8,
            "label": "Free/platform hosting with self-hosted email and no DKIM"
        },
        {
            "name": "zero_email_auth",
            "if_all": ["no_spf", "no_dkim", "no_dmarc"],
            "if_not": ["domain_gt_1yr"],
            "score": 10,
            "label": "No email authentication at all on non-established domain"
        },
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
    ],
    
    "disposable_domains": [
        'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'mailinator.com',
        'maildrop.cc', 'throwaway.email', 'getnada.com', '10minutemail.com',
        'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com',
        'fakeinbox.com', 'trashmail.com', 'tempinbox.com',
    ],
    
    "domain_blacklists": [
        "dbl.spamhaus.org",
        "multi.surbl.org", 
        "black.uribl.com",
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
                merged = DEFAULT_CONFIG.copy()
                merged.update(loaded)
                # Ensure nested dicts are merged properly
                if 'weights' in loaded:
                    merged['weights'] = {**DEFAULT_CONFIG['weights'], **loaded['weights']}
                if 'combos' in loaded:
                    merged['combos'] = {**DEFAULT_CONFIG['combos'], **loaded['combos']}
                # Rules: merge by name (user rules override defaults with same name,
                # new user rules are added). Set "rules_replace": true in config.json
                # to completely replace defaults instead of merging.
                if 'rules' in loaded:
                    if loaded.get('rules_replace', False):
                        # Full replacement mode
                        merged['rules'] = loaded['rules']
                    else:
                        # Merge mode: start with defaults, override by name, add new
                        default_rules = {r['name']: r for r in DEFAULT_CONFIG.get('rules', []) if 'name' in r}
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
    
    return DEFAULT_CONFIG.copy()


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
    """Get combo weight for two signals from config."""
    key = f"{signal1}+{signal2}"
    return config.get('combos', {}).get(key, DEFAULT_CONFIG['combos'].get(key, 0))
