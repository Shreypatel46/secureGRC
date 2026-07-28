import sys
import os
import csv
import json
import logging
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f"logs/eramba_updater_{datetime.now().strftime('%Y%m%d')}.log",
            encoding="utf-8"
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
CSV_INPUT      = "data/scored_risks.csv"
IMPORT_OUTPUT  = "data/eramba_import.csv"
SUMMARY_OUTPUT = "data/integration_summary.json"

# Only push High (BRS>=6) and Critical (BRS>=8) to Eramba
MIN_BRS = 6.0

# ── User logins from your Eramba (Settings -> Organization & Access -> Users)
# Format: "User-<login>" -- login is exactly what shows in Login column
USER_GRC        = "User-Ankit"    # Ankit Patel -- CISO, GRC owner for all risks
USER_ORIGINATOR = {
    "AcmePay Web Application":    "User-Ankit",
    "Payment Gateway API":        "User-Ankit",
    "Authentication Server":      "User-Raj",
    "Customer PII Database":      "User-Ankit",
    "AWS Production Environment": "User-Raj",
    "Developer Laptops":          "User-Priya",
    "Internal HR Portal":         "User-Ankit",
}

# ── Asset names -- must match EXACTLY what you entered in Eramba Asset Management
ASSET_NAMES = {
    "AcmePay Web Application":    "AcmePay Web Application",
    "Authentication Server":      "Authentication Server",
    "Customer PII Database":      "Customer PII Database",
    "AWS Production Environment": "AWS Production Environment",
    "Developer Laptops (x50)":    "Developer Laptops (x50)",
    "Internal HR Portal":         "Internal HR Portal",
}

# ── Threat names -- must match EXACTLY what you added in
# Risk Management -> Asset Risks -> Settings -> Threats
THREAT_MAP = {
    "AcmePay Web Application":    "Tunneling",
    "Authentication Server":      "Credential Theft",
    "Customer PII Database":      "Unauthorised records",
    "AWS Production Environment": "Spying",
    "Developer Laptops (x50)":    "Ransomware Attack",
    "Internal HR Portal":         "Credential Theft",
}

# ── Vulnerability names -- must match EXACTLY what you added in
# Risk Management -> Asset Risks -> Settings -> Vulnerabilities
VULN_MAP = {
    "AcmePay Web Application":    "No patch management process",
    "Payment Gateway API":        "No patch management process",
    "Authentication Server":      "No patch management process",
    "Customer PII Database":      "No patch management process",
    "AWS Production Environment": "Public S3 bucket misconfiguration",
    "Developer Laptops (x50)":    "Missing MDM enrollment",
    "Internal HR Portal":         "No MFA on internal portals",
}

# ── Internal control names -- must match EXACTLY what you named them in
# Control Catalog -> Internal Controls
CONTROL_MAP = {
    "AcmePay Web Application":    "A.8.8-Management of Technical Vulnerabilities",
    "Payment Gateway API":        "A.8.8-Management of Technical Vulnerabilities",
    "Authentication Server":      "A.8.5-Secure Authentication",
    "Customer PII Database":      "A.8.3-Information Access Restriction",
    "AWS Production Environment": "A.5.23-Information Security for Cloud Services",
    "Developer Laptops (x50)":          "A.8.1-User Endpoint Devices",
    "Internal HR Portal":         "A.8.5-Secure Authentication",
}

# ── Policy names -- must match EXACTLY what you named them in
# Control Catalog -> Policies
POLICY_MAP = {
    "AcmePay Web Application":    "Vulnerability Management Policy",
    "Payment Gateway API":        "Vulnerability Management Policy",
    "Authentication Server":      "Access Control Policy",
    "Customer PII Database":      "Data Classification Policy",
    "AWS Production Environment": "Cloud Security Policy",
    "Developer Laptops (x50)":          "Acceptable Use Policy",
    "Internal HR Portal":         "Access Control Policy",
}

# ── Likelihood scale 1-5 ──────────────────────────────────────────────────────
# 1=Very Low, 2=Low, 3=Medium, 4=High, 5=Very High
# Analysis = inherent (before treatment), Treatment = residual (after)
LIKELIHOOD = {
    "Critical": {"analysis": 4, "treatment": 2},
    "High":     {"analysis": 4, "treatment": 2},
    "Medium":   {"analysis": 3, "treatment": 2},
    "Low":      {"analysis": 2, "treatment": 1},
}

# ── Impact scale 6-10 ─────────────────────────────────────────────────────────
# 6=Negligible, 7=Minor, 8=Moderate, 9=Major, 10=Critical
# Eramba uses 6-10 range (not 1-5) for Impact
IMPACT = {
    "Critical": {"analysis": 10, "treatment": 9},
    "High":     {"analysis": 9,  "treatment": 8},
    "Medium":   {"analysis": 8,  "treatment": 7},
    "Low":      {"analysis": 7,  "treatment": 6},
}

# ── Treatment IDs ─────────────────────────────────────────────────────────────
# 1=Accept, 2=Avoid, 3=Mitigate, 4=Transfer
TREATMENT = {
    "Critical": 3,
    "High":     3,
    "Medium":   1,
    "Low":      1,
}

# ── Exact 20 column headers from Eramba template (copy-pasted verbatim) ────────
COL = [
    'Name (This field is mandatory, give this risk a descriptive title.)',
    'Description (Optional, describe this risk scenario, context, triggers, Etc.)',
    'Risk GRC Contact (Mandatory. Accepts multiple user logins or group names separated by "|" with a mandatory prefix. For example: Group-Admin|User-John). You can get the login of an user account from Settings / Organization & Access / Users or name of a group from Settings / Organization & Access / Groups.)',
    'Risk Originator Contact (Mandatory. Accepts multiple user logins or group names separated by "|" with a mandatory prefix. For example: Group-Admin|User-John). You can get the login of an user account from Settings / Organization & Access / Users or name of a group from Settings / Organization & Access / Groups.)',
    'Tags (Optional and accepts tags separated by "|". For example "Critical|High Risk|Financial Risk")',
    'Next Review Date (This field is mandatory, define a date when this risk will be reviewed, the format for the date is YYYY-MM-DD and the date must be in the future.)',
    'Related Assets (This field is mandatory, accepts multiple names separated by "|". You need to enter the name of an asset, you can find them at Asset Management / Asset Identification.)',
    'Threat Tags (Optional, accepts multiple names separated by "|". You need to enter the name of a threat, you can find them at Risk Management / Asset Risk Management / Settings / Threats.)',
    'Threat Description (Optional, describe the context of the threats vectors for this risk.)',
    'Vulnerabilities Tags (Optional, accepts multiple names separated by "|". You need to enter the name of a vulnerability, you can find them at Risk Management / Asset Risk Management / Settings / Vulnerabilities.)',
    'Vulnerabilities Description (Optional, describe the context of the vulnerabilities vectors for this risk.)',
    'Likelihood (Analysis) (This field is mandatory, enter one from the following options: 1 for Likelihood (Very Low), 2 for Likelihood (Low), 3 for Likelihood (Medium), 4 for Likelihood (High), 5 for Likelihood (Very High))',
    'Impact (Analysis) (This field is mandatory, enter one from the following options: 6 for Impact (Negligible), 7 for Impact (Minor), 8 for Impact (Moderate), 9 for Impact (Major), 10 for Impact (Critical))',
    'Risk Treatment (This field is mandatory, select id of treatment strategy for this risk, can be one of the following values: 1 for Accept, 2 for Avoid, 3 for Mitigate, 4 for Transfer)',
    'Treatment: Internal Controls (Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of a control, you can find them at Control Catalog / Internal Controls.)',
    'Treatment: Policies (Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of a policy, you can find them at Control Catalog / Policies.)',
    'Treatment: Risk Exceptions (Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of an exception, you can find them at Risk Management / Risk Exceptions.)',
    'Treatment: Projects (Mandatory / optional depends on "Risk Treatment" input and settings of treatment options, you can find them in risk section settings under Treatment Options. Accepts multiple names separated by "|". You need to enter the name of a project, you can find them at Security Operations / Project Management.)',
    'Likelihood (Treatment) (This field is mandatory, enter one from the following options: 1 for Likelihood (Very Low), 2 for Likelihood (Low), 3 for Likelihood (Medium), 4 for Likelihood (High), 5 for Likelihood (Very High))',
    'Impact (Treatment) (This field is mandatory, enter one from the following options: 6 for Impact (Negligible), 7 for Impact (Minor), 8 for Impact (Moderate), 9 for Impact (Major), 10 for Impact (Critical))',
]


def load_scored_risks(path: str) -> list:
    """Load scored_risks.csv into list of dicts."""
    if not os.path.exists(path):
        log.error(f"Not found: {path} -- run vuln_puller.py first")
        sys.exit(1)
    rows = []
    with open(path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row["BRS"]        = float(row["BRS"])
            row["CVSS_Score"] = float(row["CVSS_Score"])
            rows.append(row)
    log.info(f"Loaded {len(rows)} records from {path}")
    return rows


def build_row(row: dict) -> dict:
    """
    Map one scored CVE record to Eramba's 20-column import schema.
    Values are placed in the same order as COL list above.
    """
    asset   = row["Asset_Name"]
    cve_id  = row["CVE_ID"]
    brs_cls = row["BRS_Classification"]

    name = f"[AUTO] {cve_id} on {asset}"

    desc = (
        f"Auto-generated by SecureGRC scanner. "
        f"CVE {cve_id} published {row['Published_Date']}. "
        f"CVSS {row['CVSS_Score']} ({row['CVSS_Severity']}). "
        f"Asset criticality {row['Asset_Criticality']}/5, "
        f"exposure {row['Exposure_Factor']}. "
        f"Business Risk Score: {row['BRS']} ({brs_cls}). "
        f"{row['Description']}"
    )

    threat_desc = (
        f"CVE {cve_id} enables {THREAT_MAP.get(asset, 'Other')} "
        f"against {asset}. "
        f"CVSS {row['CVSS_Score']} ({row['CVSS_Severity']}) severity."
    )

    vuln_desc = (
        f"{VULN_MAP.get(asset, 'Unpatched vulnerability')} on {asset} "
        f"exposes it to {cve_id}. "
        f"Exposure factor: {row['Exposure_Factor']}."
    )

    return {
        COL[0]:  name,
        COL[1]:  desc,
        COL[2]:  USER_GRC,
        COL[3]:  USER_ORIGINATOR.get(asset, "User-Ankit"),
        COL[4]:  f"AutoScan|{brs_cls}|CVE",
        COL[5]:  "2026-12-31",
        COL[6]:  ASSET_NAMES.get(asset, asset),
        COL[7]:  THREAT_MAP.get(asset, ""),
        COL[8]:  threat_desc,
        COL[9]:  VULN_MAP.get(asset, ""),
        COL[10]: vuln_desc,
        COL[11]: LIKELIHOOD[brs_cls]["analysis"],
        COL[12]: IMPACT[brs_cls]["analysis"],
        COL[13]: TREATMENT[brs_cls],
        COL[14]: CONTROL_MAP.get(asset, ""),
        COL[15]: POLICY_MAP.get(asset, ""),
        COL[16]: "",
        COL[17]: "",
        COL[18]: LIKELIHOOD[brs_cls]["treatment"],
        COL[19]: IMPACT[brs_cls]["treatment"],
    }


def save_csv(rows: list, path: str) -> None:
    """Write import CSV with exact Eramba headers, all fields quoted."""
    if not rows:
        log.warning("No rows to export")
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=COL,
            quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(rows)
    log.info(f"Import CSV saved: {path} ({len(rows)} rows)")


def save_json(stats: dict, rows: list, path: str) -> None:
    """Save JSON audit trail."""
    out = {
        "run_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats":         stats,
        "exported_risks": [
            {
                "name":       r[COL[0]],
                "asset":      r[COL[6]],
                "likelihood": r[COL[11]],
                "impact":     r[COL[12]],
                "treatment":  r[COL[13]],
                "control":    r[COL[14]],
                "policy":     r[COL[15]],
            }
            for r in rows
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    log.info(f"JSON summary saved: {path}")


def print_summary(stats: dict) -> None:
    print("\n" + "=" * 60)
    print("  SECUREGRC -- ERAMBA INTEGRATION SUMMARY")
    print("=" * 60)
    print(f"  Total CVEs in scored_risks.csv : {stats['total']}")
    print(f"  High/Critical exported         : {stats['pushed']}")
    print(f"  Low/Medium skipped             : {stats['skipped']}")
    print(f"\n  Files generated:")
    print(f"    data/eramba_import.csv        <- upload this to Eramba")
    print(f"    data/integration_summary.json <- audit trail")
    print(f"\n  IMPORT STEPS:")
    print(f"    1. Eramba -> Risk Management -> Asset Risks")
    print(f"    2. Settings (top right) -> Import Tool")
    print(f"    3. Upload data/eramba_import.csv")
    print(f"    4. Eramba auto-maps columns from template headers")
    print(f"    5. Review and confirm import")
    print("=" * 60 + "\n")


def main():
    log.info("=" * 55)
    log.info("SecureGRC -- Eramba Integration Engine")
    log.info(f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info(f"Min BRS   : {MIN_BRS} (High + Critical only)")
    log.info("=" * 55)

    all_risks = load_scored_risks(CSV_INPUT)
    pushable  = [r for r in all_risks if r["BRS"] >= MIN_BRS]
    skipped   = len(all_risks) - len(pushable)

    log.info(f"Exporting {len(pushable)} High/Critical risks")
    log.info(f"Skipping  {skipped} Low/Medium risks")

    export_rows = []
    for row in pushable:
        export_rows.append(build_row(row))
        log.info(
            f"  [{row['BRS_Classification']}] {row['CVE_ID']} | "
            f"BRS:{row['BRS']} | {row['Asset_Name']}"
        )

    save_csv(export_rows, IMPORT_OUTPUT)

    stats = {"total": len(all_risks), "pushed": len(pushable), "skipped": skipped}
    save_json(stats, export_rows, SUMMARY_OUTPUT)
    print_summary(stats)


if __name__ == "__main__":
    main()