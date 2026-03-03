"""
ICANN RDAP Proxy Fallback
=========================
Slot this into the domain age lookup chain:
  1. RDAP (direct bootstrap) — current
  2. ICANN RDAP proxy (rdap.org) — NEW FALLBACK
  3. python-whois — current fallback

The ICANN proxy (rdap.org) maintains broader ccTLD coverage than the
IANA bootstrap file alone. It resolves .ng, .ke, .gh, .tz, .za, and
many other ccTLDs that standard RDAP libraries miss.

Integration points:
  - Call icann_rdap_fallback() when your existing RDAP lookup returns
    no creation date AND python-whois also fails
  - If this returns valid data, use it to populate domain age fields
    and suppress the REGISTRATION OPAQUE signal
  - Update the reason string to indicate the source:
    "Domain age: X days (via ICANN RDAP proxy)" or similar
"""

import requests
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict


def icann_rdap_fallback(domain: str, timeout: float = 8.0) -> Dict:
    """
    Query ICANN's RDAP proxy (rdap.org) as a fallback when direct RDAP
    and python-whois both fail to return registration data.
    
    rdap.org acts as a bootstrap redirector with broader ccTLD coverage
    than the IANA bootstrap file used by most RDAP libraries.
    
    Returns:
        dict with keys:
            - creation_date: ISO string or ""
            - creation_days_ago: int (-1 if unavailable)
            - updated_date: ISO string or ""
            - updated_days_ago: int (-1 if unavailable)
            - expiration_date: ISO string or ""
            - registrar: str
            - source: "icann_rdap_proxy" (for audit/logging)
    """
    result = {
        "creation_date": "",
        "creation_days_ago": -1,
        "updated_date": "",
        "updated_days_ago": -1,
        "expiration_date": "",
        "registrar": "",
        "source": "icann_rdap_proxy",
    }

    # Extract base domain (handle subdomains)
    parts = domain.lower().strip().split(".")
    # Handle compound ccTLDs like .co.uk, .com.ng, .co.za
    compound_slds = {"co", "com", "org", "net", "ac", "gov", "edu"}
    if len(parts) > 2 and parts[-2] in compound_slds:
        base = ".".join(parts[-3:])
    else:
        base = ".".join(parts[-2:])

    # rdap.org is the ICANN-operated bootstrap proxy
    # It redirects to the authoritative RDAP server for the TLD
    url = f"https://rdap.org/domain/{base}"

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "DomainApproval/7.5 (OneSignal Trust & Safety)",
            },
            allow_redirects=True,  # rdap.org redirects to authoritative server
        )

        if resp.status_code != 200:
            return result

        data = resp.json()

        # --- Extract dates from RDAP events array ---
        # RDAP spec: events[] with eventAction = "registration", "last changed", "expiration"
        events = data.get("events", [])
        now = datetime.now(timezone.utc)

        for event in events:
            action = event.get("eventAction", "").lower()
            date_str = event.get("eventDate", "")

            if not date_str:
                continue

            try:
                dt = _parse_rdap_date(date_str)
            except (ValueError, TypeError):
                continue

            if action == "registration":
                result["creation_date"] = dt.isoformat()
                result["creation_days_ago"] = (now - dt).days

            elif action in ("last changed", "last update of rdap database"):
                # Only use "last changed" — skip "last update of rdap database"
                # which is the registry mirror sync, not the domain update
                if action == "last changed":
                    result["updated_date"] = dt.isoformat()
                    result["updated_days_ago"] = (now - dt).days

            elif action == "expiration":
                result["expiration_date"] = dt.isoformat()

        # --- Extract registrar from entities array ---
        # RDAP spec: entities[] with roles including "registrar"
        for entity in data.get("entities", []):
            roles = [r.lower() for r in entity.get("roles", [])]
            if "registrar" in roles:
                # Try vcardArray first (structured), then handle/publicIds
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            result["registrar"] = str(field[3])[:200]
                            break
                if not result["registrar"]:
                    result["registrar"] = entity.get("handle", "")[:200]
                break

    except requests.exceptions.Timeout:
        pass  # Don't let slow ccTLD registries block the pipeline
    except requests.exceptions.ConnectionError:
        pass
    except (ValueError, KeyError):
        pass  # Malformed JSON
    except Exception:
        pass  # Catch-all — never let this fallback crash the scorer

    return result


def _parse_rdap_date(date_str: str) -> datetime:
    """
    Parse RDAP date strings. Registries aren't consistent — handle:
      - 2024-06-15T12:00:00Z
      - 2024-06-15T12:00:00+00:00
      - 2024-06-15 (date only)
    """
    date_str = date_str.strip()

    # Try ISO format first (handles Z and +00:00)
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    # Fallback: date only
    try:
        dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise


# ──────────────────────────────────────────────────────────────
# Integration example — where to call this in your existing chain
# ──────────────────────────────────────────────────────────────
#
# def get_domain_age(domain: str) -> Tuple[str, int]:
#     """Existing domain age function — add ICANN fallback."""
#     
#     # Step 1: Try direct RDAP (existing)
#     creation_date, age_days = rdap_lookup(domain)
#     if age_days >= 0:
#         return creation_date, age_days
#     
#     # Step 2: Try python-whois (existing)
#     creation_date, age_days = whois_lookup(domain)
#     if age_days >= 0:
#         return creation_date, age_days
#     
#     # Step 3: ICANN RDAP proxy fallback (NEW)
#     icann = icann_rdap_fallback(domain)
#     if icann["creation_days_ago"] >= 0:
#         return icann["creation_date"], icann["creation_days_ago"]
#     
#     # All lookups failed — REGISTRATION OPAQUE still applies
#     return "", -1
#
#
# For whois_enrich() integration, also check icann results:
#
# def whois_enrich(domain: str) -> dict:
#     result = _existing_whois_enrich(domain)
#     
#     # If python-whois missed registrar/dates, try ICANN proxy
#     if not result["registrar"] or result["updated_days_ago"] == -1:
#         icann = icann_rdap_fallback(domain)
#         if icann["registrar"] and not result["registrar"]:
#             result["registrar"] = icann["registrar"]
#         if icann["updated_days_ago"] >= 0 and result["updated_days_ago"] == -1:
#             result["updated_date"] = icann["updated_date"]
#             result["updated_days_ago"] = icann["updated_days_ago"]
#     
#     return result  
