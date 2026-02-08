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
        "status_403_cloaking": 15,
        "status_429_throttling": 8,
        "status_503_disposable": 8,
        "status_5xx_errors": 4,
        "minimal_shell": 10,
        "js_redirect": 8,
        "meta_refresh": 5,
        "external_js_loader": 6,
        "obfuscated_js": 10,
        "phishing_paths": 15,
        "form_posts_external": 10,
        "suspicious_iframe": 8,
        "parking_page": 6,
        
        # === BONUSES (Reduce score) ===
        "has_bimi": -10,
        "has_mta_sts": -6,
    },
    
    "combos": {
        # Fraud combos (high additional penalty - these are real red flags)
        "typosquat_detected+credential_form": 30,
        "typosquat_detected+domain_lt_30d": 25,
        "brand_impersonation+credential_form": 30,
        "brand_impersonation+domain_lt_30d": 20,
        "domain_blacklisted+domain_lt_30d": 25,
        
        # Deliverability combos (LOW penalties - these shouldn't cause deny)
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
        
        # Suspicious behavior combos
        "no_https+redirect_temp_302_307": 8,
        "domain_lt_30d+redirect_chain_2plus": 6,
        "domain_lt_7d+redirect_chain_2plus": 10,
        "status_403_cloaking+domain_lt_30d": 10,
        "minimal_shell+js_redirect": 10,
        "credential_form+no_https": 8,
        "phishing_paths+credential_form": 12,
        "free_email_domain+credential_form": 10,
        "disposable_email+no_spf": 8,
        "disposable_email+domain_lt_30d": 15,
        "no_ptr+domain_lt_30d": 4,
        "ptr_mismatch+domain_blacklisted": 10,
    },
    
    "suspicious_tlds": [
        '.xyz', '.top', '.work', '.click', '.link', '.info', '.biz', '.online',
        '.site', '.website', '.space', '.fun', '.icu', '.buzz', '.club',
        '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov',
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
