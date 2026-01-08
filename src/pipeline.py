"""
OSINT IOC Enrichment Pipeline (Educational)
-----------------------------------------
Demonstrates:
- IOC extraction from text/URLs
- Normalization & de-duplication
- Enrichment via public threat-intel APIs (pluggable)
- Simple data pipeline with storage and export

NOTE:
- This code is READ-ONLY OSINT.
- Do not scrape private content or violate ToS.
- API keys are loaded from environment variables.
"""

import re
import json
import time
import argparse
import logging
import os
from typing import List, Dict

import requests
from bs4 import BeautifulSoup

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# -----------------------------
# IOC REGEX PATTERNS
# -----------------------------
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

# -----------------------------
# SCRAPING
# -----------------------------

def fetch_url_text(url: str, timeout: int = 10) -> str:
    """Fetches visible text from a public web page."""
    logger.info(f"Fetching URL: {url}")
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "OSINT-Research-Bot/1.0"})
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")

    # Remove scripts/styles
    for tag in soup(["script", "style"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    return " ".join(text.split())

# -----------------------------
# IOC EXTRACTION
# -----------------------------

def extract_iocs(text: str, source: str) -> List[Dict]:
    """Extracts IOCs from text and normalizes them."""
    found = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.findall(text):
            found.append({
                "ioc": match.lower(),
                "type": ioc_type,
                "source": source
            })
    return found


def deduplicate_iocs(iocs: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for item in iocs:
        key = (item["ioc"], item["type"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique

# -----------------------------
# ENRICHMENT (PLUGGABLE)
# -----------------------------

def enrich_with_abuseipdb(ip: str) -> Dict:
    """Example enrichment using AbuseIPDB (community/free)."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set; skipping enrichment")
        return {}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    r = requests.get(url, headers=headers, params=params, timeout=10)
    if r.status_code != 200:
        logger.error(f"AbuseIPDB error for {ip}: {r.status_code}")
        return {}

    data = r.json().get("data", {})
    return {
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "countryCode": data.get("countryCode"),
        "usageType": data.get("usageType")
    }


def enrich_ioc(ioc: Dict) -> Dict:
    enriched = dict(ioc)
    if ioc["type"] == "ipv4":
        enriched["enrichment"] = enrich_with_abuseipdb(ioc["ioc"])
        time.sleep(1)  # rate limiting
    else:
        enriched["enrichment"] = {}
    return enriched

# -----------------------------
# PIPELINE
# -----------------------------

def run_pipeline(urls: List[str], output_file: str):
    all_iocs = []

    for url in urls:
        try:
            text = fetch_url_text(url)
            extracted = extract_iocs(text, source=url)
            all_iocs.extend(extracted)
        except Exception as e:
            logger.error(f"Failed processing {url}: {e}")

    unique_iocs = deduplicate_iocs(all_iocs)
    logger.info(f"Unique IOCs found: {len(unique_iocs)}")

    enriched_iocs = []
    for ioc in unique_iocs:
        enriched_iocs.append(enrich_ioc(ioc))

    with open(output_file, "w") as f:
        json.dump(enriched_iocs, f, indent=2)

    logger.info(f"Results written to {output_file}")

# -----------------------------
# CLI
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="OSINT IOC Enrichment Pipeline")
    parser.add_argument("--urls", nargs="+", required=True, help="Public URLs to scan")
    parser.add_argument("--out", default="output.json", help="Output JSON file")
    args = parser.parse_args()

    run_pipeline(args.urls, args.out)


if __name__ == "__main__":
    main()
