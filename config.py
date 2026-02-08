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
        # Email Authentication
        "no_spf": 25,
        "spf_pass_all": 35,
        "spf_neutral_all": 15,
        "spf_softfail_all": 5,
        "spf_too_many_lookups": 10,
        "spf_syntax_error": 10,
        "no_dmarc": 28,
        "dmarc_p_none": 12,
        "dmarc_no_rua": 3,
        "dmarc_syntax_error": 10,
        "no_dkim": 22,
        "no_mx": 25,
        "null_mx": 20,
        "mx_free_provider": 15,
        
        # Reverse DNS
        "no_ptr": 12,
        "ptr_mismatch": 15,
        
        # Bonuses (negative = reduces score)
        "has_bimi": -5,
        "has_mta_sts": -5,
        
        # Blacklists
        "domain_blacklisted": 35,
        "ip_blacklisted": 30,
        
        # Domain Age
        "domain_lt_7d": 30,
        "domain_lt_30d": 20,
        "domain_lt_90d": 8,
        
        # Domain Type
        "suspicious_tld": 12,
        "free_email_domain": 20,
        "free_hosting": 12,
        "url_shortener": 8,
        "disposable_email": 30,
        "typosquat_detected": 25,
        
        # Web/TLS
        "no_https": 25,
        "http_accessible": 5,
        "cert_self_signed": 12,
        "cert_expired": 15,
        "cert_wrong_host": 15,
        "redirect_chain_2plus": 12,
        "redirect_chain_3plus": 8,
        "redirect_cross_domain": 12,
        "redirect_temp_302_307": 10,
        
        # Status Codes
        "status_403_cloaking": 20,
        "status_429_throttling": 15,
        "status_503_disposable": 15,
        "status_5xx_errors": 8,
        
        # Content
        "minimal_shell": 15,
        "js_redirect": 12,
        "meta_refresh": 8,
        "external_js_loader": 10,
        "obfuscated_js": 12,
        
        # Phishing/Malware
        "phishing_paths": 20,
        "credential_form": 20,
        "sensitive_fields": 18,
        "brand_impersonation": 22,
        "form_posts_external": 18,
        "malware_links": 25,
        "suspicious_iframe": 12,
        "parking_page": 10,
    },
    
    "combos": {
        "no_spf+no_dmarc": 15,
        "spf_pass_all+no_dmarc": 20,
        "no_dkim+no_dmarc": 15,
        "no_spf+no_dkim": 12,
        "no_spf+domain_lt_30d": 12,
        "no_dmarc+domain_lt_30d": 12,
        "no_dkim+domain_lt_30d": 10,
        "no_spf+domain_lt_7d": 18,
        "no_dmarc+domain_lt_7d": 18,
        "no_mx+domain_lt_30d": 15,
        "domain_blacklisted+domain_lt_30d": 20,
        "no_https+redirect_temp_302_307": 15,
        "domain_lt_30d+redirect_chain_2plus": 12,
        "domain_lt_7d+redirect_chain_2plus": 15,
        "status_403_cloaking+domain_lt_30d": 15,
        "minimal_shell+js_redirect": 15,
        "brand_impersonation+domain_lt_30d": 20,
        "brand_impersonation+credential_form": 18,
        "credential_form+no_https": 15,
        "phishing_paths+credential_form": 15,
        "free_email_domain+credential_form": 15,
        "typosquat_detected+credential_form": 25,
        "typosquat_detected+domain_lt_30d": 20,
        "disposable_email+no_spf": 15,
        "disposable_email+domain_lt_30d": 18,
        "no_ptr+domain_lt_30d": 10,
        "ptr_mismatch+domain_blacklisted": 15,
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
