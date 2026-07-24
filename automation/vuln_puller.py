"""
vuln_puller.py
SecureGRC Project — Milestone M4
Automated Vulnerability Risk Engine

What this does:
  1. Defines AcmeCorp's asset inventory with criticality and exposure ratings
  2. Queries the NIST NVD CVE API for each asset's software
  3. Parses CVSS scores from the JSON response
  4. Calculates a Business Risk Score (BRS) for each CVE
  5. Classifies each CVE as Critical / High / Medium / Low
  6. Saves raw data as JSON and scored results as CSV

Author: SecureGRC Project
"""

import requests
import json
import csv
import time
import os
import logging
from datetime import datetime
import sys
sys.stdout.reconfigure(encoding="utf-8")
# ── Logging setup ──────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f"logs/vuln_scan_{datetime.now().strftime('%Y%m%d')}.log",
            encoding="utf-8"
        ),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── AcmeCorp Asset Inventory ───────────────────────────────────────────────────
# Each asset has:
#   name        : matches asset name in Eramba
#   keyword     : search term for NVD CVE API
#   criticality : 1-5 based on Eramba asset classification
#   exposure    : 1.0=internet-facing, 0.7=internal, 0.4=air-gapped

ASSETS = [
    {
        "name": "AcmePay Web Application",
        "keyword": "apache http server",
        "criticality": 5,
        "exposure": 1.0
    },
    {
        "name": "Payment Gateway API",
        "keyword": "nginx",
        "criticality": 5,
        "exposure": 1.0
    },
    {
        "name": "Authentication Server",
        "keyword": "openssl",
        "criticality": 5,
        "exposure": 0.7
    },
    {
        "name": "Customer PII Database",
        "keyword": "mysql",
        "criticality": 5,
        "exposure": 0.4
    },
    {
        "name": "AWS Production Environment",
        "keyword": "amazon aws",
        "criticality": 5,
        "exposure": 1.0
    },
    {
        "name": "Developer Laptops",
        "keyword": "python",
        "criticality": 3,
        "exposure": 0.7
    },
    {
        "name": "Internal HR Portal",
        "keyword": "php",
        "criticality": 2,
        "exposure": 0.7
    },
]

# ── NVD API Configuration ──────────────────────────────────────────────────────
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 10       # max CVEs to fetch per asset
RATE_LIMIT_SLEEP = 7        # seconds between requests (NVD allows 5 req/30s)


def fetch_cves(keyword: str) -> list:
    """
    Query NVD API for CVEs matching a keyword.
    Returns list of vulnerability dicts from the API response.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": 0
    }

    log.info(f"Querying NVD API: '{keyword}'")

    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            timeout=20,
            headers={"User-Agent": "SecureGRC-Scanner/1.0"}
        )
        response.raise_for_status()
        data = response.json()
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        log.info(f"  → {total} total CVEs in NVD, fetched top {len(vulns)}")
        return vulns

    except requests.exceptions.Timeout:
        log.error(f"  → Timeout querying NVD for '{keyword}' — skipping")
        return []
    except requests.exceptions.HTTPError as e:
        log.error(f"  → HTTP error for '{keyword}': {e}")
        return []
    except requests.exceptions.RequestException as e:
        log.error(f"  → Request failed for '{keyword}': {e}")
        return []


def parse_cvss_score(vuln: dict) -> tuple:
    """
    Extract CVSS base score and version from a vulnerability dict.
    Priority: CVSSv3.1 > CVSSv3.0 > CVSSv2
    Returns (score, version) tuple.
    """
    try:
        metrics = vuln["cve"]["metrics"]

        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            return round(score, 1), "3.1"

        elif "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            return round(score, 1), "3.0"

        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            return round(score, 1), "2.0"

    except (KeyError, IndexError):
        pass

    return 0.0, "N/A"


def calculate_brs(cvss: float, criticality: int, exposure: float) -> float:
    """
    Business Risk Score formula:
    BRS = (CVSS_Base × Asset_Criticality × Exposure_Factor) / 5

    Max possible raw score = 10 × 5 × 1.0 = 50
    Dividing by 5 normalises to 0-10 scale.

    Examples:
      Critical internet-facing asset: (9.8 × 5 × 1.0) / 5 = 9.8
      Internal low-criticality asset: (9.8 × 2 × 0.7) / 5 = 2.74
    """
    if cvss == 0.0:
        return 0.0
    raw = cvss * criticality * exposure
    normalised = round(raw / 5, 2)
    return min(normalised, 10.0)


def classify_brs(brs: float) -> str:
    """
    Map BRS score to risk classification.
    Thresholds align with our Eramba Risk Appetite configuration.
    """
    if brs >= 8.0:
        return "Critical"
    elif brs >= 6.0:
        return "High"
    elif brs >= 4.0:
        return "Medium"
    else:
        return "Low"


def get_severity_from_cvss(cvss: float) -> str:
    """Standard CVSS severity labels for reference."""
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0.0:
        return "Low"
    return "None"


def process_asset(asset: dict) -> list:
    """
    Full pipeline for one asset:
    fetch CVEs → parse scores → calculate BRS → return scored records.
    """
    results = []
    vulns = fetch_cves(asset["keyword"])

    if not vulns:
        log.warning(f"  No CVEs returned for {asset['name']}")
        return results

    for vuln in vulns:
        try:
            cve_id = vuln["cve"]["id"]

            # Get description (English preferred)
            descriptions = vuln["cve"].get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )[:200]

            # Parse scores
            cvss_score, cvss_version = parse_cvss_score(vuln)
            cvss_severity = get_severity_from_cvss(cvss_score)

            # Calculate Business Risk Score
            brs = calculate_brs(
                cvss_score,
                asset["criticality"],
                asset["exposure"]
            )
            brs_classification = classify_brs(brs)

            # Published date
            published = vuln["cve"].get("published", "")[:10]

            record = {
                "Asset_Name":        asset["name"],
                "CVE_ID":            cve_id,
                "CVSS_Version":      cvss_version,
                "CVSS_Score":        cvss_score,
                "CVSS_Severity":     cvss_severity,
                "Asset_Criticality": asset["criticality"],
                "Exposure_Factor":   asset["exposure"],
                "BRS":               brs,
                "BRS_Classification": brs_classification,
                "Published_Date":    published,
                "Description":       description
            }

            results.append(record)

            log.info(
                f"  {cve_id} | CVSS:{cvss_score}({cvss_severity}) "
                f"| BRS:{brs} -> {brs_classification}"
            )

        except Exception as e:
            log.error(f"  Error processing {vuln.get('cve', {}).get('id', 'unknown')}: {e}")
            continue

    return results


def save_json(data: list, timestamp: str) -> str:
    """Save raw scored results to JSON file."""
    os.makedirs("data", exist_ok=True)
    path = f"data/raw_vulns_{timestamp}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    log.info(f"Raw JSON saved: {path}")
    return path


def save_csv(data: list) -> str:
    """Save scored results to CSV for risk register use."""
    os.makedirs("data", exist_ok=True)
    path = "data/scored_risks.csv"
    if not data:
        log.warning("No data to save to CSV")
        return path
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    log.info(f"Scored CSV saved: {path}")
    return path


def print_summary(results: list) -> None:
    """Print a clean summary to the terminal."""
    print("\n" + "=" * 65)
    print("  SECUREGRC — VULNERABILITY SCAN SUMMARY")
    print("=" * 65)

    if not results:
        print("  No vulnerabilities found.")
        return

    # Count by BRS classification
    for level in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for r in results if r["BRS_Classification"] == level)
        bar = "█" * count
        print(f"  {level:<10} {bar} ({count})")

    print(f"\n  Total CVEs scored: {len(results)}")
    print(f"  Assets scanned:    {len(ASSETS)}")

    # Top 5 by BRS
    top5 = sorted(results, key=lambda x: x["BRS"], reverse=True)[:5]
    print("\n  TOP 5 HIGHEST BUSINESS RISK SCORES:")
    print(f"  {'CVE ID':<20} {'Asset':<35} {'BRS':<6} {'Class'}")
    print("  " + "-" * 70)
    for r in top5:
        print(
            f"  {r['CVE_ID']:<20} "
            f"{r['Asset_Name']:<35} "
            f"{r['BRS']:<6} "
            f"{r['BRS_Classification']}"
        )
    print("=" * 65 + "\n")


def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    log.info("=" * 55)
    log.info("SecureGRC Vulnerability Risk Engine — Starting")
    log.info(f"Timestamp: {timestamp}")
    log.info(f"Assets to scan: {len(ASSETS)}")
    log.info("=" * 55)

    all_results = []

    for i, asset in enumerate(ASSETS):
        log.info(f"\n[{i+1}/{len(ASSETS)}] Processing: {asset['name']}")
        log.info(f"  Keyword: {asset['keyword']} | "
                 f"Criticality: {asset['criticality']} | "
                 f"Exposure: {asset['exposure']}")

        asset_results = process_asset(asset)
        all_results.extend(asset_results)

        # Rate limit — NVD allows 5 requests per 30 seconds without API key
        if i < len(ASSETS) - 1:
            log.info(f"  Waiting {RATE_LIMIT_SLEEP}s (NVD rate limit)...")
            time.sleep(RATE_LIMIT_SLEEP)

    # Save outputs
    json_path = save_json(all_results, timestamp)
    csv_path = save_csv(all_results)

    # Print summary
    print_summary(all_results)

    log.info("Scan complete.")
    log.info(f"JSON: {json_path}")
    log.info(f"CSV:  {csv_path}")


if __name__ == "__main__":
    main()