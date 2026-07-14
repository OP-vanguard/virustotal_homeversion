"""
vt_client.py
Queries the VirusTotal API v3 for a file hash, IP address, domain, or URL and
returns a structured report. For file hashes: detection ratio, malware family,
first/last seen dates, known filenames, file type/size. For IPs and domains:
detection ratio, reputation, country/ASN (IP) or registrar info (domain), and
categorization. For URLs: detection ratio, final redirected URL, and page title
if available.

Reads the API key from a .env file (VT_API_KEY=...) so the key never gets
hardcoded into source or committed to git. Requires: pip install python-dotenv requests
"""

import os
import re
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_FILES_URL = "https://www.virustotal.com/api/v3/files/"
VT_IPS_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
VT_DOMAINS_URL = "https://www.virustotal.com/api/v3/domains/"
VT_URLS_URL = "https://www.virustotal.com/api/v3/urls/"


class VTClientError(Exception):
    """Raised for any VT API issue - missing key, bad response, rate limit, etc."""
    pass


# --- Input type detection -------------------------------------------------

HASH_PATTERNS = {32: "md5", 40: "sha1", 64: "sha256"}

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
URL_SCHEME_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


def is_hash(value: str) -> bool:
    """True if value is a plain hex string of MD5/SHA1/SHA256 length."""
    return bool(re.fullmatch(r"[a-fA-F0-9]+", value)) and len(value) in HASH_PATTERNS


def _is_valid_ip(value: str) -> bool:
    if not IP_PATTERN.match(value):
        return False
    return all(0 <= int(octet) <= 255 for octet in value.split("."))


def is_ip(value: str) -> bool:
    """True if value is a valid IPv4 address."""
    return _is_valid_ip(value)


def is_url(value: str) -> bool:
    """True if value starts with http:// or https:// -- checked before is_domain
    since a URL like http://evil.com/path would not match the plain domain regex
    anyway, but checking explicitly avoids relying on that as the only signal."""
    return bool(URL_SCHEME_PATTERN.match(value))


def is_domain(value: str) -> bool:
    """True if value looks like a bare domain name (no scheme/path) and isn't an IP."""
    return bool(DOMAIN_PATTERN.match(value)) and not is_ip(value)


def identify_target_type(value: str) -> str:
    """Returns 'hash', 'url', 'ip', 'domain', or 'unknown' for a given input string.
    Order matters: check url before domain, since a URL's host portion could
    otherwise be mistaken for a bare domain if checked in the wrong order."""
    if is_hash(value):
        return "hash"
    if is_url(value):
        return "url"
    if is_ip(value):
        return "ip"
    if is_domain(value):
        return "domain"
    return "unknown"


# --- Shared request handling ------------------------------------------------

def _vt_get(url: str) -> dict:
    """Shared GET logic with consistent error handling across all VT endpoints."""
    if not VT_API_KEY:
        raise VTClientError(
            "No VT_API_KEY found. Make sure you have a .env file in your project "
            "root with a line like: VT_API_KEY=your_key_here"
        )

    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        raise VTClientError(f"Network error contacting VirusTotal: {e}")

    if response.status_code == 404:
        return {"found": False, "_status": 404}
    if response.status_code == 401:
        raise VTClientError("VT API key rejected (401). Double check your key in .env")
    if response.status_code == 429:
        raise VTClientError(
            "VT rate limit hit (429). Free tier = 4 requests/minute. Wait a bit and retry."
        )
    if response.status_code != 200:
        raise VTClientError(f"Unexpected VT response: {response.status_code} - {response.text}")

    return response.json()


# --- File hash lookup --------------------------------------------------------

def query_vt(file_hash: str) -> dict:
    """Query VirusTotal for a given file hash (MD5, SHA1, or SHA256)."""
    result = _vt_get(VT_FILES_URL + file_hash)

    if result.get("_status") == 404:
        return {
            "found": False,
            "hash": file_hash,
            "message": "This hash has no record in VirusTotal's database.",
        }

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    threat_classification = attributes.get("popular_threat_classification", {})
    family = threat_classification.get("suggested_threat_label", "unknown")

    return {
        "found": True,
        "target_type": "hash",
        "hash": file_hash,
        "detection_ratio": f"{malicious}/{total_engines}",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "threat_family": family,
        "file_type": attributes.get("type_description", "unknown"),
        "file_size": attributes.get("size", "unknown"),
        "known_filenames": attributes.get("names", [])[:5],
        "first_submission": attributes.get("first_submission_date"),
        "last_analysis": attributes.get("last_analysis_date"),
        "reputation": attributes.get("reputation", "unknown"),
    }


# --- IP address lookup -------------------------------------------------------

def query_vt_ip(ip: str) -> dict:
    """Query VirusTotal for a given IPv4 address."""
    result = _vt_get(VT_IPS_URL + ip)

    if result.get("_status") == 404:
        return {
            "found": False,
            "ip": ip,
            "message": "This IP has no record in VirusTotal's database.",
        }

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    return {
        "found": True,
        "target_type": "ip",
        "ip": ip,
        "detection_ratio": f"{malicious}/{total_engines}",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "reputation": attributes.get("reputation", "unknown"),
        "country": attributes.get("country", "unknown"),
        "asn": attributes.get("asn", "unknown"),
        "as_owner": attributes.get("as_owner", "unknown"),
        "network": attributes.get("network", "unknown"),
        "last_analysis": attributes.get("last_analysis_date"),
    }


# --- Domain lookup -------------------------------------------------------------

def query_vt_domain(domain: str) -> dict:
    """Query VirusTotal for a given domain name."""
    result = _vt_get(VT_DOMAINS_URL + domain)

    if result.get("_status") == 404:
        return {
            "found": False,
            "domain": domain,
            "message": "This domain has no record in VirusTotal's database.",
        }

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    categories = attributes.get("categories", {})

    return {
        "found": True,
        "target_type": "domain",
        "domain": domain,
        "detection_ratio": f"{malicious}/{total_engines}",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "reputation": attributes.get("reputation", "unknown"),
        "registrar": attributes.get("registrar", "unknown"),
        "creation_date": attributes.get("creation_date"),
        "categories": list(categories.values()) if categories else [],
        "last_analysis": attributes.get("last_analysis_date"),
    }


# --- URL lookup ----------------------------------------------------------------

def _vt_url_id(url: str) -> str:
    """
    VT identifies URLs by base64-encoding them (URL-safe alphabet, no padding),
    not by using the raw URL as a path segment. This matches VT API v3 spec:
    https://docs.virustotal.com/reference/url
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def query_vt_url(url: str) -> dict:
    """
    Query VirusTotal for a given URL. Note: this only retrieves an EXISTING
    analysis -- if VT has never scanned this URL before, it returns not-found
    rather than triggering a fresh scan (submitting a new URL for scanning is
    a separate POST endpoint, out of scope for a read-only lookup tool).
    """
    url_id = _vt_url_id(url)
    result = _vt_get(VT_URLS_URL + url_id)

    if result.get("_status") == 404:
        return {
            "found": False,
            "url": url,
            "message": "This URL has no existing record in VirusTotal's database. "
                       "VT hasn't scanned it before -- submitting new URLs for "
                       "scanning isn't supported by this lookup tool.",
        }

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    return {
        "found": True,
        "target_type": "url",
        "url": url,
        "detection_ratio": f"{malicious}/{total_engines}",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "reputation": attributes.get("reputation", "unknown"),
        "final_url": attributes.get("last_final_url", url),
        "title": attributes.get("title", "unknown"),
        "times_submitted": attributes.get("times_submitted", 0),
        "last_analysis": attributes.get("last_analysis_date"),
    }


# --- Unified dispatcher -------------------------------------------------------

def query_vt_auto(target: str) -> dict:
    """
    Detects whether target is a hash, URL, IP, or domain and calls the right
    query function. Raises VTClientError if target type can't be identified.
    """
    target_type = identify_target_type(target)

    if target_type == "hash":
        return query_vt(target)
    elif target_type == "url":
        return query_vt_url(target)
    elif target_type == "ip":
        return query_vt_ip(target)
    elif target_type == "domain":
        return query_vt_domain(target)
    else:
        raise VTClientError(
            f"Could not identify '{target}' as a hash, URL, IP, or domain. "
            "Check the input format."
        )


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python3 vt_client.py <hash|url|ip|domain>")
        sys.exit(1)

    try:
        result = query_vt_auto(sys.argv[1])
        print(json.dumps(result, indent=2))
    except VTClientError as e:
        print(f"Error: {e}")
        sys.exit(1)
