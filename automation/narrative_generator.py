import sys
import os
import csv
import json
import requests
import logging
import time
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs",    exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("prompts", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f"logs/narrative_{datetime.now().strftime('%Y%m%d')}.log",
            encoding="utf-8"
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
OLLAMA_URL       = "http://localhost:11434/api/generate"
OLLAMA_MODEL     = "mistral"
OLLAMA_TIMEOUT   = 300          # seconds -- LLM can take time for long outputs

CSV_INPUT        = "data/scored_risks.csv"
SUMMARY_INPUT    = "data/integration_summary.json"
EXEC_PROMPT_FILE = "prompts/executive_prompt.txt"
TECH_PROMPT_FILE = "prompts/technical_prompt.txt"
EXEC_OUTPUT      = "reports/executive_risk_summary.md"
TECH_OUTPUT      = "reports/technical_briefing.md"

TOP_N_RISKS      = 10           # feed top N risks to LLM
COMPANY_NAME     = "AcmeCorp"
REPORT_DATE      = datetime.now().strftime("%Y-%m-%d")


def load_scored_risks(path: str) -> list:
    """Load and sort scored_risks.csv by BRS descending."""
    if not os.path.exists(path):
        log.error(f"Not found: {path} -- run vuln_puller.py first")
        sys.exit(1)
    rows = []
    with open(path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row["BRS"]        = float(row["BRS"])
            row["CVSS_Score"] = float(row["CVSS_Score"])
            rows.append(row)
    rows.sort(key=lambda x: x["BRS"], reverse=True)
    log.info(f"Loaded {len(rows)} CVE records, sorted by BRS")
    return rows


def load_integration_summary(path: str) -> dict:
    """Load integration_summary.json from eramba_updater.py."""
    if not os.path.exists(path):
        log.warning(f"Integration summary not found: {path} -- using defaults")
        return {"stats": {"total": 0, "pushed": 0, "skipped": 0}}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_prompt_template(path: str) -> str:
    """Load prompt template from file."""
    if not os.path.exists(path):
        log.error(f"Prompt template not found: {path}")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def build_risk_context(risks: list, top_n: int) -> str:
    """
    Build a structured text block of the top N risks
    to inject into the LLM prompt as context.
    """
    top = risks[:top_n]
    lines = [
        f"VULNERABILITY SCAN RESULTS -- {COMPANY_NAME}",
        f"Scan Date: {REPORT_DATE}",
        f"Total CVEs scored: {len(risks)}",
        f"Showing top {len(top)} by Business Risk Score (BRS)",
        "",
        f"{'#':<4} {'CVE ID':<20} {'Asset':<30} {'CVSS':<6} {'BRS':<6} {'Class':<10} Published",
        "-" * 90,
    ]

    for i, r in enumerate(top, 1):
        lines.append(
            f"{i:<4} {r['CVE_ID']:<20} {r['Asset_Name']:<30} "
            f"{r['CVSS_Score']:<6} {r['BRS']:<6} {r['BRS_Classification']:<10} "
            f"{r['Published_Date']}"
        )

    lines += [
        "",
        "ASSET CONTEXT:",
        "- AcmePay Web Application: customer-facing payment app, internet-facing, criticality 5/5",
        "- Payment Gateway API: processes all payment transactions, internet-facing, criticality 5/5",
        "- Authentication Server: handles all user sessions, internal, criticality 5/5",
        "- Customer PII Database: stores PII for all customers, air-gapped, criticality 5/5",
        "- AWS Production Environment: primary cloud infrastructure, internet-facing, criticality 5/5",
        "- Developer Laptops: 50 developer endpoints, internal, criticality 3/5",
        "- Internal HR Portal: employee data portal, internal, criticality 2/5",
        "",
        "ISO 27001 CONTROL GAPS (from gap analysis):",
        "- A.8.8 Vulnerability Management: NOT IMPLEMENTED",
        "- A.8.2 Privileged Access Rights: NOT IMPLEMENTED",
        "- A.8.16 Monitoring Activities: NOT IMPLEMENTED",
        "- A.8.12 Data Leakage Prevention: NOT IMPLEMENTED",
        "- A.8.9 Configuration Management: NOT IMPLEMENTED",
        "- A.5.23 Cloud Services Security: NOT IMPLEMENTED",
        "- A.8.5 Secure Authentication: IMPLEMENTED",
        "- A.8.7 Malware Protection: IMPLEMENTED",
        "- A.8.24 Cryptography: IMPLEMENTED",
        "",
        "BRS FORMULA: BRS = (CVSS_Base x Asset_Criticality x Exposure_Factor) / 5",
        "Exposure: 1.0=internet-facing, 0.7=internal, 0.4=air-gapped",
        "Classification: Critical(>=8), High(>=6), Medium(>=4), Low(<4)",
    ]

    return "\n".join(lines)


def build_eramba_context(summary: dict) -> str:
    """Add Eramba integration stats to the prompt context."""
    stats = summary.get("stats", {})
    return (
        f"\nGRC PLATFORM STATUS (Eramba):\n"
        f"- Total CVEs processed by automation: {stats.get('total', 'N/A')}\n"
        f"- High/Critical risks pushed to risk register: {stats.get('pushed', 'N/A')}\n"
        f"- Low/Medium risks filtered out: {stats.get('skipped', 'N/A')}\n"
        f"- Platform: Eramba Community Edition (ISO 27001 GRC)\n"
    )


def call_ollama(prompt: str, model: str = OLLAMA_MODEL) -> str:
    """
    Call Ollama local LLM API.
    POST to http://localhost:11434/api/generate
    stream=false returns complete response in one JSON blob.
    """
    payload = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,    # lower = more focused, factual output
            "num_predict": 2048,   # max tokens to generate
        }
    }

    log.info(f"Calling Ollama ({model}) -- this may take 30-90 seconds...")
    start = time.time()

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )
        response.raise_for_status()
        data     = response.json()
        elapsed  = round(time.time() - start, 1)
        text     = data.get("response", "").strip()
        log.info(f"Ollama response received in {elapsed}s ({len(text)} chars)")
        return text

    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to Ollama at localhost:11434")
        log.error("Make sure Ollama is running: open Ollama from Start menu")
        sys.exit(1)
    except requests.exceptions.Timeout:
        log.error(f"Ollama timed out after {OLLAMA_TIMEOUT}s")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        log.error(f"Ollama API error: {e}")
        sys.exit(1)


def save_report(content: str, path: str, title: str) -> None:
    """Save generated report to markdown file with metadata header."""
    header = (
        f"<!-- Generated by SecureGRC narrative_generator.py -->\n"
        f"<!-- Date: {REPORT_DATE} | Model: {OLLAMA_MODEL} | Company: {COMPANY_NAME} -->\n\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(header + content)
    log.info(f"{title} saved: {path}")


def generate_executive_report(risks: list, summary: dict) -> None:
    """Generate board/CISO-level executive risk summary."""
    log.info("\n--- Generating Executive Risk Summary ---")

    template    = load_prompt_template(EXEC_PROMPT_FILE)
    risk_ctx    = build_risk_context(risks, TOP_N_RISKS)
    eramba_ctx  = build_eramba_context(summary)

    full_prompt = f"{template}\n\n{risk_ctx}\n{eramba_ctx}"

    log.info(f"Prompt length: {len(full_prompt)} chars")
    response = call_ollama(full_prompt)
    save_report(response, EXEC_OUTPUT, "Executive Risk Summary")


def generate_technical_report(risks: list, summary: dict) -> None:
    """Generate security-team-level technical risk briefing."""
    log.info("\n--- Generating Technical Risk Briefing ---")

    template   = load_prompt_template(TECH_PROMPT_FILE)
    risk_ctx   = build_risk_context(risks, TOP_N_RISKS)
    eramba_ctx = build_eramba_context(summary)

    full_prompt = f"{template}\n\n{risk_ctx}\n{eramba_ctx}"

    log.info(f"Prompt length: {len(full_prompt)} chars")
    response = call_ollama(full_prompt)
    save_report(response, TECH_OUTPUT, "Technical Risk Briefing")


def verify_ollama() -> bool:
    """Check Ollama is running and mistral model is available."""
    try:
        r = requests.get("http://localhost:11434", timeout=5)
        if "Ollama" in r.text or r.status_code == 200:
            log.info("Ollama is running")
        # Check model exists
        r2 = requests.get("http://localhost:11434/api/tags", timeout=5)
        models = [m["name"] for m in r2.json().get("models", [])]
        log.info(f"Available models: {models}")
        if not any(OLLAMA_MODEL in m for m in models):
            log.error(f"Model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}")
            return False
        return True
    except requests.exceptions.ConnectionError:
        log.error("Ollama not running. Open Ollama from Start menu first.")
        return False


def print_summary(exec_path: str, tech_path: str) -> None:
    print(f"  Executive Summary : {exec_path}")
    print(f"  Technical Briefing: {tech_path}")
    

def main():
    log.info("=" * 55)
    log.info("SecureGRC -- AI Risk Narrative Generator")
    log.info(f"Model  : {OLLAMA_MODEL} via Ollama localhost")
    log.info(f"Date   : {REPORT_DATE}")
    log.info("=" * 55)

    # Step 1 -- verify Ollama is up
    if not verify_ollama():
        sys.exit(1)

    # Step 2 -- load data
    risks   = load_scored_risks(CSV_INPUT)
    summary = load_integration_summary(SUMMARY_INPUT)

    # Step 3 -- generate executive report
    generate_executive_report(risks, summary)

    # Step 4 -- generate technical briefing
    generate_technical_report(risks, summary)

    # Step 5 -- summary
    print_summary(EXEC_OUTPUT, TECH_OUTPUT)


if __name__ == "__main__":
    main()