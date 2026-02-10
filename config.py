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
    "admin_password": "**********",  # CHANGE THIS!
    
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
        "dmarc_p_none": 5,            # p=none - not protecting but not fraud
        "dmarc_no_rua": 2,            # No reporting - trivial
        "dmarc_syntax_error": 4,
        "no_dkim": 6,                 # Missing DKIM - deliverability issue only
        "no_mx": 8,                   # No MX - can't receive bounces
        "null_mx": 12,
        "mx_free_provider": 6,
        
        # === INFRASTRUCTURE CONCERNS (Low weights) ===
        "no_ptr": 4,                  # Missing PTR - minor
        "ptr_mismatch": 5,
        "no_https": 8,                # No HTTPS - minor concern
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
    },
    
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
