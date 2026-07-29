import sys
import subprocess
import time
import os
import logging
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f"logs/pipeline_{datetime.now().strftime('%Y%m%d_%H%M')}.log",
            encoding="utf-8"
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ── Pipeline scripts ───────────────────────────────────────────────────────────
SCRIPTS = {
    "scan":      "automation/vuln_puller.py",
    "score":     "automation/risk_scorer.py",
    "update":    "automation/eramba_updater.py",
    "narrative": "automation/narrative_generator.py",
    "dashboard": "automation/dashboard.py",
}


def run_step(name: str, script: str) -> bool:
    """
    Run one pipeline step as a subprocess.
    Returns True if exit code is 0, False otherwise.
    Streams output live to terminal.
    """
    print(f"\n{'='*60}")
    print(f"  PIPELINE STEP: {name.upper()}")
    print(f"  Script: {script}")
    print(f"  Started: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")

    start  = time.time()
    result = subprocess.run(
        [sys.executable, script],
        text=True
    )
    elapsed = round(time.time() - start, 1)

    if result.returncode == 0:
        log.info(f"[OK] {name} completed in {elapsed}s")
        return True
    else:
        log.error(f"[FAIL] {name} failed after {elapsed}s (exit code {result.returncode})")
        return False


def print_final_summary(results: dict, total_time: float) -> None:
    print(f"\n{'='*60}")
    print("  SECUREGRC PIPELINE -- FINAL SUMMARY")
    print(f"{'='*60}")
    all_ok = True
    for step, success in results.items():
        status = "OK  " if success else "FAIL"
        icon   = "+" if success else "x"
        print(f"  [{icon}] [{status}] {step}")
        if not success:
            all_ok = False
    print(f"\n  Total time : {total_time}s")
    print(f"  Finished   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Status     : {'ALL STEPS PASSED' if all_ok else 'SOME STEPS FAILED'}")
    print(f"\n  Output files:")
    print(f"    data/scored_risks.csv              <- BRS scored vulnerabilities")
    print(f"    data/eramba_import.csv             <- ready for Eramba import")
    print(f"    data/integration_summary.json      <- audit trail")
    print(f"    reports/risk_heatmap.png           <- ISO 27001 heat map")
    print(f"    reports/brs_distribution.png       <- BRS chart")
    print(f"    reports/executive_risk_summary.md  <- CISO/board report")
    print(f"    reports/technical_briefing.md      <- security team report")
    print(f"{'='*60}\n")


def main():
    args          = sys.argv[1:]
    pipeline_start = time.time()
    results        = {}

    print(f"\n{'='*60}")
    print("  SECUREGRC -- FULL PIPELINE ORCHESTRATOR")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode: {args[0] if args else 'full pipeline'}")
    print(f"{'='*60}")

    # ── Mode: narrative only ───────────────────────────────────────────────────
    if "--narrative-only" in args:
        results["narrative"] = run_step(
            "AI Risk Narrative", SCRIPTS["narrative"]
        )

    # ── Mode: update only ─────────────────────────────────────────────────────
    elif "--update-only" in args:
        results["update"] = run_step(
            "Eramba Import Generator", SCRIPTS["update"]
        )

    # ── Mode: scan only ───────────────────────────────────────────────────────
    elif "--scan-only" in args:
        results["scan"] = run_step(
            "NVD Vulnerability Scanner", SCRIPTS["scan"]
        )
        if results["scan"]:
            results["score"] = run_step(
                "BRS Scorer and Visualisation", SCRIPTS["score"]
            )
        else:
            log.error("Scan failed -- skipping score step")

    # ── Mode: full pipeline ───────────────────────────────────────────────────
    else:
        # Step 1 -- Vulnerability scan
        results["scan"] = run_step(
            "NVD Vulnerability Scanner", SCRIPTS["scan"]
        )
        if not results["scan"]:
            log.error("Scan failed -- stopping pipeline")
            print_final_summary(results, round(time.time() - pipeline_start, 1))
            sys.exit(1)

        # Step 2 -- BRS scoring and visualisation
        results["score"] = run_step(
            "BRS Scorer and Visualisation", SCRIPTS["score"]
        )
        if not results["score"]:
            log.warning("Score step failed -- continuing to update step")

        # Step 3 -- Eramba import CSV generation
        results["update"] = run_step(
            "Eramba Import Generator", SCRIPTS["update"]
        )
        if not results["update"]:
            log.warning("Eramba update failed -- continuing to narrative step")

        # Step 4 -- AI narrative generation
        results["narrative"] = run_step(
            "AI Risk Narrative (Ollama)", SCRIPTS["narrative"]
        )
        # Step 5 -- Compliance dashboard
        results["dashboard"] = run_step(
            "GRC Compliance Dashboard", SCRIPTS["dashboard"]
        )

    total_time = round(time.time() - pipeline_start, 1)
    print_final_summary(results, total_time)

    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()