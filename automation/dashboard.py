import sys
import os
import csv
import json
import base64
import io
import logging
from datetime import datetime, timedelta

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")
os.makedirs("logs",    exist_ok=True)
os.makedirs("reports", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f"logs/dashboard_{datetime.now().strftime('%Y%m%d')}.log",
            encoding="utf-8"
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
CSV_INPUT       = "data/scored_risks.csv"
SUMMARY_INPUT   = "data/integration_summary.json"
HEATMAP_INPUT   = "reports/risk_heatmap.png"
BARCHART_INPUT  = "reports/brs_distribution.png"
HTML_OUTPUT     = "reports/grc_dashboard_report.html"
REPORT_DATE     = datetime.now().strftime("%Y-%m-%d")
REPORT_DT       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── ISO 27001 control audit data (from M1 Eramba work) ────────────────────────
CONTROLS = [
    {"id":"A.5.1",  "name":"Policies for Information Security",       "domain":"A.5 Organizational", "status":"Partial"},
    {"id":"A.5.15", "name":"Access Control",                          "domain":"A.5 Organizational", "status":"Implemented"},
    {"id":"A.5.23", "name":"Information Security for Cloud Services", "domain":"A.5 Organizational", "status":"Not Implemented"},
    {"id":"A.6.3",  "name":"Information Security Awareness Training", "domain":"A.6 People",         "status":"Partial"},
    {"id":"A.6.8",  "name":"Information Security Event Reporting",    "domain":"A.6 People",         "status":"Not Implemented"},
    {"id":"A.7.1",  "name":"Physical Security Perimeters",            "domain":"A.7 Physical",       "status":"Implemented"},
    {"id":"A.7.4",  "name":"Physical Security Monitoring",            "domain":"A.7 Physical",       "status":"Partial"},
    {"id":"A.8.1",  "name":"User Endpoint Devices",                   "domain":"A.8 Technological",  "status":"Partial"},
    {"id":"A.8.2",  "name":"Privileged Access Rights",                "domain":"A.8 Technological",  "status":"Not Implemented"},
    {"id":"A.8.3",  "name":"Information Access Restriction",          "domain":"A.8 Technological",  "status":"Partial"},
    {"id":"A.8.5",  "name":"Secure Authentication",                   "domain":"A.8 Technological",  "status":"Implemented"},
    {"id":"A.8.7",  "name":"Protection Against Malware",              "domain":"A.8 Technological",  "status":"Implemented"},
    {"id":"A.8.8",  "name":"Management of Technical Vulnerabilities", "domain":"A.8 Technological",  "status":"Not Implemented"},
    {"id":"A.8.9",  "name":"Configuration Management",                "domain":"A.8 Technological",  "status":"Not Implemented"},
    {"id":"A.8.12", "name":"Data Leakage Prevention",                 "domain":"A.8 Technological",  "status":"Not Implemented"},
    {"id":"A.8.15", "name":"Logging",                                 "domain":"A.8 Technological",  "status":"Partial"},
    {"id":"A.8.16", "name":"Monitoring Activities",                   "domain":"A.8 Technological",  "status":"Not Implemented"},
    {"id":"A.8.24", "name":"Use of Cryptography",                     "domain":"A.8 Technological",  "status":"Implemented"},
    {"id":"A.8.28", "name":"Secure Coding",                           "domain":"A.8 Technological",  "status":"Partial"},
    {"id":"A.8.32", "name":"Change Management",                       "domain":"A.8 Technological",  "status":"Partial"},
]

C = {
    "green":  "#4CAF50",
    "orange": "#F4A226",
    "red":    "#D7263D",
    "yellow": "#F4E04D",
    "blue":   "#89B4FA",
    "purple": "#CBA6F7",
}

STATUS_COLOUR = {
    "Implemented":     C["green"],
    "Partial":         C["orange"],
    "Not Implemented": C["red"],
}

BRS_COLOUR = {
    "Critical": C["red"],
    "High":     C["orange"],
    "Medium":   C["yellow"],
    "Low":      C["green"],
}


# ── Loaders ────────────────────────────────────────────────────────────────────

def load_risks() -> pd.DataFrame:
    if not os.path.exists(CSV_INPUT):
        log.warning(f"{CSV_INPUT} not found -- using empty dataset")
        return pd.DataFrame(columns=[
            "Asset_Name","CVE_ID","Published_Date","CVSS_Score",
            "CVSS_Severity","Asset_Criticality","Exposure_Factor",
            "BRS","BRS_Classification","Description"
        ])
    df = pd.read_csv(CSV_INPUT, encoding="utf-8-sig")
    df["BRS"]        = pd.to_numeric(df["BRS"],        errors="coerce").fillna(0)
    df["CVSS_Score"] = pd.to_numeric(df["CVSS_Score"], errors="coerce").fillna(0)
    log.info(f"Loaded {len(df)} CVE records")
    return df


def load_summary() -> dict:
    if not os.path.exists(SUMMARY_INPUT):
        log.warning(f"{SUMMARY_INPUT} not found -- using defaults")
        return {"stats": {"total": 0, "pushed": 0, "skipped": 0}}
    with open(SUMMARY_INPUT, encoding="utf-8") as f:
        return json.load(f)


# ── Compliance calculations ────────────────────────────────────────────────────

def calc_compliance() -> dict:
    df      = pd.DataFrame(CONTROLS)
    total   = len(df)
    impl    = int((df["status"] == "Implemented").sum())
    partial = int((df["status"] == "Partial").sum())
    not_im  = int((df["status"] == "Not Implemented").sum())
    score   = round(((impl * 1.0 + partial * 0.5) / total) * 100, 1)
    rating  = (
        "CRITICAL"  if score < 40 else
        "HIGH RISK" if score < 60 else
        "MODERATE"  if score < 80 else
        "GOOD"
    )
    return {
        "total": total, "implemented": impl,
        "partial": partial, "not_implemented": not_im,
        "score": score, "rating": rating,
    }


def domain_scores() -> list:
    """Return list of (domain, score%) sorted ascending."""
    df = pd.DataFrame(CONTROLS)
    score_map = {"Implemented": 1.0, "Partial": 0.5, "Not Implemented": 0.0}
    df["s"] = df["status"].map(score_map)
    result = (
        df.groupby("domain")["s"].mean() * 100
    ).sort_values().reset_index()
    result.columns = ["domain", "pct"]
    return result.to_dict("records")


def risk_rating(df: pd.DataFrame) -> str:
    if df.empty:
        return "UNKNOWN"
    crits = int((df["BRS_Classification"] == "Critical").sum())
    highs = int((df["BRS_Classification"] == "High").sum())
    if crits >= 3: return "CRITICAL"
    if crits >= 1: return "HIGH"
    if highs >= 5: return "HIGH"
    return "MEDIUM"


# ── Chart helpers ──────────────────────────────────────────────────────────────

BG    = "#1E1E2E"
SURF  = "#2A2A3E"


def fig_to_b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130,
                bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def file_to_b64(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


# ── Individual charts ──────────────────────────────────────────────────────────

def chart_donut(compliance: dict) -> str:
    impl    = compliance["implemented"]
    partial = compliance["partial"]
    not_im  = compliance["not_implemented"]
    sizes   = [impl, partial, not_im]
    labels  = ["Implemented", "Partial", "Not Implemented"]
    colors  = [C["green"], C["orange"], C["red"]]

    fig, ax = plt.subplots(figsize=(5, 4.5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    wedges, _, autotexts = ax.pie(
        sizes, colors=colors, autopct="%1.0f%%",
        startangle=90,
        wedgeprops={"width": 0.52, "edgecolor": BG, "linewidth": 2},
        pctdistance=0.76,
    )
    for at in autotexts:
        at.set_color("white")
        at.set_fontsize(10)
        at.set_fontweight("bold")

    ax.text(0, 0.06, f"{compliance['score']}%",
            ha="center", va="center",
            color="white", fontsize=18, fontweight="bold")
    ax.text(0, -0.18, "Score",
            ha="center", va="center",
            color="#888AAA", fontsize=10)

    legend_patches = [
        mpatches.Patch(color=colors[i], label=f"{labels[i]} ({sizes[i]})")
        for i in range(3)
    ]
    ax.legend(handles=legend_patches, loc="lower center",
              bbox_to_anchor=(0.5, -0.06), ncol=1,
              framealpha=0.1, labelcolor="white", fontsize=8)
    ax.set_title("Control Implementation", color="white", fontsize=11, pad=10)
    return fig_to_b64(fig)


def chart_domain(domains: list) -> str:
    labels = [d["domain"].split()[0] + "\n" + " ".join(d["domain"].split()[1:])
              for d in domains]
    values = [d["pct"] for d in domains]
    colors = [
        C["green"] if v >= 70 else C["orange"] if v >= 40 else C["red"]
        for v in values
    ]

    fig, ax = plt.subplots(figsize=(6, 3.8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(SURF)

    bars = ax.barh(labels, values, color=colors,
                   edgecolor=BG, linewidth=1.5, height=0.5)
    for bar, val in zip(bars, values):
        ax.text(val + 1, bar.get_y() + bar.get_height() / 2,
                f"{val:.0f}%", va="center",
                color="white", fontsize=10, fontweight="bold")

    ax.axvline(x=70, color="white", linestyle="--",
               linewidth=1, alpha=0.35, label="Target 70%")
    ax.set_xlim(0, 115)
    ax.set_xlabel("Compliance %", color="#888AAA", fontsize=9)
    ax.tick_params(colors="white", labelsize=9)
    ax.set_title("Score by ISO Domain", color="white", fontsize=11, pad=10)
    for sp in ax.spines.values():
        sp.set_edgecolor("#444466")
    plt.tight_layout()
    return fig_to_b64(fig)


def chart_severity(df: pd.DataFrame) -> str:
    levels = ["Critical", "High", "Medium", "Low"]
    counts = [int((df["BRS_Classification"] == l).sum()) for l in levels]
    colors = [BRS_COLOUR[l] for l in levels]

    fig, ax = plt.subplots(figsize=(5, 3.8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(SURF)

    bars = ax.bar(levels, counts, color=colors,
                  edgecolor=BG, linewidth=1.5, width=0.5)
    for bar, cnt in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.2,
                str(cnt), ha="center", va="bottom",
                fontsize=13, fontweight="bold", color="white")

    ax.set_ylabel("CVE Count", color="#888AAA", fontsize=9)
    ax.set_title("Risk Severity Distribution", color="white", fontsize=11, pad=10)
    ax.tick_params(colors="white")
    for sp in ax.spines.values():
        sp.set_edgecolor("#444466")
    plt.tight_layout()
    return fig_to_b64(fig)


def chart_trend() -> str:
    months = [
        (datetime.now() - timedelta(days=30 * i)).strftime("%b %Y")
        for i in range(5, -1, -1)
    ]
    impl_data  = [15, 17, 20, 22, 25, 30]
    part_data  = [35, 35, 38, 40, 40, 40]
    notim_data = [50, 48, 42, 38, 35, 30]

    fig, ax = plt.subplots(figsize=(8, 3.8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(SURF)

    ax.plot(months, impl_data,  "o-", color=C["green"],  lw=2, ms=6,
            label="Implemented")
    ax.plot(months, part_data,  "s-", color=C["orange"], lw=2, ms=6,
            label="Partial")
    ax.plot(months, notim_data, "^-", color=C["red"],    lw=2, ms=6,
            label="Not Implemented")
    ax.fill_between(months, impl_data, alpha=0.12, color=C["green"])

    ax.set_ylabel("% of Controls", color="#888AAA", fontsize=9)
    ax.set_title("6-Month Compliance Trend (Simulated)",
                 color="white", fontsize=11, pad=10)
    ax.tick_params(colors="white", labelsize=8)
    ax.legend(labelcolor="white", framealpha=0.15, fontsize=9)
    for sp in ax.spines.values():
        sp.set_edgecolor("#444466")
    plt.xticks(rotation=12)
    plt.tight_layout()
    return fig_to_b64(fig)


# ── HTML fragments ─────────────────────────────────────────────────────────────

def html_top10(df: pd.DataFrame) -> str:
    if df.empty:
        return "<tr><td colspan='6' style='text-align:center;color:#888'>No risk data available</td></tr>"
    top10 = df.nlargest(10, "BRS")
    rows  = ""
    for _, r in top10.iterrows():
        cls   = str(r.get("BRS_Classification", "Low"))
        color = BRS_COLOUR.get(cls, "#888")
        rows += f"""
<tr>
  <td><code style="color:#89b4fa;font-size:12px">{r['CVE_ID']}</code></td>
  <td style="font-size:12px">{r['Asset_Name']}</td>
  <td style="text-align:center;font-size:12px">{r['Published_Date']}</td>
  <td style="text-align:center">{r['CVSS_Score']}</td>
  <td style="text-align:center;font-weight:700">{r['BRS']}</td>
  <td style="text-align:center">
    <span style="background:{color};color:#fff;padding:2px 9px;
      border-radius:4px;font-size:11px;font-weight:700">{cls}</span>
  </td>
</tr>"""
    return rows


def html_controls() -> str:
    rows = ""
    for c in CONTROLS:
        col = STATUS_COLOUR.get(c["status"], "#888")
        rows += f"""
<tr>
  <td><code style="color:#89b4fa;font-size:12px">{c['id']}</code></td>
  <td style="font-size:12px">{c['name']}</td>
  <td style="font-size:11px;color:#cba6f7">{c['domain']}</td>
  <td style="text-align:center">
    <span style="background:{col};color:#fff;padding:2px 8px;
      border-radius:4px;font-size:11px;font-weight:700">{c['status']}</span>
  </td>
</tr>"""
    return rows


def img_tag(b64: str, alt: str = "") -> str:
    if not b64:
        return f"<p style='color:#888;font-size:12px'>Image not found — run risk_scorer.py first</p>"
    return f'<img src="data:image/png;base64,{b64}" alt="{alt}" style="max-width:100%;border-radius:8px">'


# ── HTML builder ───────────────────────────────────────────────────────────────

CSS = """
:root {
  --bg:#1E1E2E; --surf:#2A2A3E; --border:#444466;
  --text:#CDD6F4; --muted:#888AAA; --accent:#89B4FA; --purple:#CBA6F7;
  --red:#D7263D; --orange:#F4A226; --yellow:#F4E04D; --green:#4CAF50;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);
  font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
.page{max-width:1100px;margin:0 auto;padding:32px 20px}

.header{
  background:linear-gradient(135deg,#1a1a2e 0%,#16213e 55%,#0f3460 100%);
  border:1px solid var(--border);border-radius:12px;
  padding:28px 32px;margin-bottom:20px;
  display:flex;justify-content:space-between;align-items:center;gap:20px
}
.header h1{font-size:24px;font-weight:600;color:var(--accent)}
.header p{color:var(--muted);font-size:12px;margin-top:5px}
.badge{text-align:center;padding:14px 22px;border-radius:10px;min-width:140px}

.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.card{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:18px 20px}
.card .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.card .val{font-size:28px;font-weight:700;margin-top:4px}
.card .sub{font-size:11px;color:var(--muted);margin-top:3px}

.sec{background:var(--surf);border:1px solid var(--border);
  border-radius:10px;padding:22px;margin-bottom:18px}
.sec h2{font-size:14px;font-weight:600;color:var(--accent);
  margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:8px}
.sec h2::before{content:'';display:inline-block;
  width:3px;height:15px;background:var(--accent);border-radius:2px}

.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}
.g2 .sec{margin-bottom:0}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}

table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#16213e;color:var(--muted);font-size:10px;
  text-transform:uppercase;letter-spacing:.06em;
  padding:9px 12px;text-align:left;border-bottom:1px solid var(--border)}
td{padding:8px 12px;border-bottom:1px solid #33334a}
tr:hover td{background:#ffffff07}
tr:last-child td{border-bottom:none}

.exec-box{background:#16213e;border-left:3px solid var(--accent);
  border-radius:0 8px 8px 0;padding:14px 18px;
  font-size:13px;line-height:1.75;color:var(--text)}

.stat-mini{background:#16213e;border:1px solid var(--border);
  border-radius:8px;padding:14px;text-align:center}
.stat-mini .big{font-size:26px;font-weight:700}
.stat-mini .lbl{font-size:11px;color:var(--muted);margin-top:3px}

.footer{text-align:center;color:var(--muted);font-size:11px;
  margin-top:28px;padding-top:18px;border-top:1px solid var(--border)}
code{font-family:'Consolas','Courier New',monospace}
"""


def build_html(
    df: pd.DataFrame,
    summary: dict,
    compliance: dict,
    charts: dict,
) -> str:

    rating       = risk_rating(df)
    rating_color = {"CRITICAL": C["red"], "HIGH": C["orange"],
                    "MEDIUM": C["yellow"], "GOOD": C["green"],
                    "UNKNOWN": "#888"}.get(rating, "#888")
    comp_color   = (C["red"] if compliance["score"] < 40 else
                    C["orange"] if compliance["score"] < 60 else
                    C["yellow"] if compliance["score"] < 80 else C["green"])

    stats    = summary.get("stats", {})
    total_cv = len(df)
    crits    = int((df["BRS_Classification"] == "Critical").sum()) if not df.empty else 0
    highs    = int((df["BRS_Classification"] == "High").sum())     if not df.empty else 0
    meds     = int((df["BRS_Classification"] == "Medium").sum())   if not df.empty else 0
    lows     = int((df["BRS_Classification"] == "Low").sum())      if not df.empty else 0
    avg_brs  = round(df["BRS"].mean(), 2) if not df.empty else 0

    domains   = domain_scores()
    domain_bars = ""
    for d in sorted(domains, key=lambda x: x["pct"], reverse=True):
        pct   = d["pct"]
        col   = C["green"] if pct >= 70 else C["orange"] if pct >= 40 else C["red"]
        domain_bars += f"""
<div style="margin-bottom:10px">
  <div style="display:flex;justify-content:space-between;
    font-size:12px;margin-bottom:3px">
    <span>{d['domain']}</span>
    <span style="color:{col};font-weight:700">{pct:.0f}%</span>
  </div>
  <div style="height:7px;background:#33334a;border-radius:4px;overflow:hidden">
    <div style="width:{pct}%;height:100%;background:{col};border-radius:4px"></div>
  </div>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureGRC — GRC Compliance Dashboard | AcmeCorp</title>
<style>{CSS}</style>
</head>
<body>
<div class="page">

<!-- HEADER -->
<div class="header">
  <div>
    <h1>SecureGRC &mdash; ISO 27001 Compliance Dashboard</h1>
    <p>AcmeCorp Fintech &nbsp;&bull;&nbsp; Report Date: {REPORT_DATE} &nbsp;&bull;&nbsp; Generated by SecureGRC Pipeline</p>
    <p style="margin-top:6px;font-size:11px;color:var(--accent)">
      NVD CVE Intelligence &bull; BRS Scoring Engine &bull; Eramba GRC Platform &bull; Ollama AI Narrative
    </p>
  </div>
  <div style="display:flex;gap:12px">
    <div class="badge" style="border:2px solid {rating_color};background:{rating_color}22">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Risk Rating</div>
      <div style="font-size:20px;font-weight:700;color:{rating_color};margin-top:3px">{rating}</div>
    </div>
    <div class="badge" style="border:2px solid {comp_color};background:{comp_color}22">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Compliance</div>
      <div style="font-size:20px;font-weight:700;color:{comp_color};margin-top:3px">{compliance['score']}%</div>
    </div>
  </div>
</div>

<!-- STAT CARDS -->
<div class="cards">
  <div class="card">
    <div class="lbl">Total CVEs Scored</div>
    <div class="val" style="color:var(--accent)">{total_cv}</div>
    <div class="sub">Across 7 AcmeCorp assets</div>
  </div>
  <div class="card">
    <div class="lbl">Critical + High</div>
    <div class="val" style="color:var(--red)">{crits + highs}</div>
    <div class="sub">{crits} Critical &bull; {highs} High BRS</div>
  </div>
  <div class="card">
    <div class="lbl">Avg Business Risk Score</div>
    <div class="val" style="color:var(--orange)">{avg_brs}</div>
    <div class="sub">Max 10.0 &bull; BRS formula</div>
  </div>
  <div class="card">
    <div class="lbl">Controls Implemented</div>
    <div class="val" style="color:var(--green)">{compliance['implemented']}/{compliance['total']}</div>
    <div class="sub">ISO 27001:2022 Annex A</div>
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="sec">
  <h2>Executive Summary</h2>
  <div class="exec-box">
    AcmeCorp's current information security posture presents a
    <strong style="color:{rating_color}">{rating}</strong> risk to business operations.
    Automated vulnerability intelligence from the NIST National Vulnerability Database
    identified <strong>{total_cv} CVEs</strong> across 7 critical assets,
    with <strong style="color:var(--red)">{crits} Critical</strong> and
    <strong style="color:var(--orange)">{highs} High</strong> Business Risk Score
    vulnerabilities requiring immediate remediation.
    <br><br>
    Of {compliance['total']} ISO 27001:2022 Annex A controls assessed,
    <strong style="color:var(--green)">{compliance['implemented']} are fully implemented</strong>,
    <strong style="color:var(--orange)">{compliance['partial']} are partially implemented</strong>, and
    <strong style="color:var(--red)">{compliance['not_implemented']} have not been implemented</strong>.
    The overall compliance score of <strong style="color:{comp_color}">{compliance['score']}%</strong>
    indicates significant investment is required to achieve ISO 27001 certification readiness.
    <br><br>
    <strong>Priority actions:</strong>
    Implement <code style="color:var(--accent)">A.8.8</code> Vulnerability Management,
    <code style="color:var(--accent)">A.8.2</code> Privileged Access Rights, and
    <code style="color:var(--accent)">A.8.16</code> Monitoring Activities —
    the three critical unimplemented controls that directly map to the highest-scoring CVE risks.
  </div>
</div>

<!-- COMPLIANCE + DOMAIN -->
<div class="g2">
  <div class="sec">
    <h2>Control Implementation Status</h2>
    {img_tag(charts['donut'],'Control Status Donut')}
  </div>
  <div class="sec">
    <h2>Compliance by ISO 27001 Domain</h2>
    <div style="margin-top:4px">{domain_bars}</div>
    <div style="margin-top:14px">
      {img_tag(charts['domain'],'Domain Compliance Chart')}
    </div>
  </div>
</div>

<!-- SEVERITY + HEAT MAP -->
<div class="g2">
  <div class="sec">
    <h2>Risk Severity Distribution</h2>
    {img_tag(charts['severity'],'Risk Severity Chart')}
    <div class="g2" style="margin-top:14px;gap:8px">
      <div style="display:contents">
        <div style="grid-column:1/3">
          <div class="g2" style="gap:8px">
            <div class="stat-mini" style="border-color:var(--red)">
              <div class="big" style="color:var(--red)">{crits}</div>
              <div class="lbl">Critical</div>
            </div>
            <div class="stat-mini" style="border-color:var(--orange)">
              <div class="big" style="color:var(--orange)">{highs}</div>
              <div class="lbl">High</div>
            </div>
          </div>
          <div class="g2" style="gap:8px;margin-top:8px">
            <div class="stat-mini" style="border-color:var(--yellow)">
              <div class="big" style="color:#c8b400">{meds}</div>
              <div class="lbl">Medium</div>
            </div>
            <div class="stat-mini" style="border-color:var(--green)">
              <div class="big" style="color:var(--green)">{lows}</div>
              <div class="lbl">Low</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div class="sec">
    <h2>ISO 27001 Risk Heat Map</h2>
    {img_tag(charts['heatmap'],'Risk Heat Map')}
  </div>
</div>

<!-- TOP 10 RISKS -->
<div class="sec">
  <h2>Top 10 Vulnerabilities by Business Risk Score</h2>
  <table>
    <thead>
      <tr>
        <th>CVE ID</th><th>Asset</th><th>Published</th>
        <th>CVSS</th><th>BRS</th><th>Classification</th>
      </tr>
    </thead>
    <tbody>{html_top10(df)}</tbody>
  </table>
</div>

<!-- BRS DISTRIBUTION -->
<div class="sec">
  <h2>Business Risk Score Distribution by Asset</h2>
  {img_tag(charts['barchart'],'BRS Distribution')}
</div>

<!-- CONTROL TABLE -->
<div class="sec">
  <h2>ISO 27001:2022 Annex A &mdash; Control Implementation Register</h2>
  <table>
    <thead>
      <tr><th>Control ID</th><th>Control Name</th><th>Domain</th><th>Status</th></tr>
    </thead>
    <tbody>{html_controls()}</tbody>
  </table>
</div>

<!-- TREND -->
<div class="sec">
  <h2>Compliance Trend &mdash; 6 Month View (Simulated)</h2>
  <p style="color:var(--muted);font-size:12px;margin-bottom:12px">
    Projected compliance improvement trajectory as remediation actions are completed.
    Simulation based on current gap analysis and planned treatment priorities.
  </p>
  {img_tag(charts['trend'],'Compliance Trend')}
</div>

<!-- ERAMBA STATS -->
<div class="sec">
  <h2>GRC Platform Integration &mdash; Eramba Community</h2>
  <div class="g3">
    <div class="stat-mini" style="border:1px solid var(--accent)">
      <div class="big" style="color:var(--accent)">{stats.get('total',0)}</div>
      <div class="lbl">Total CVEs Processed by Automation</div>
    </div>
    <div class="stat-mini" style="border:1px solid var(--red)">
      <div class="big" style="color:var(--red)">{stats.get('pushed',0)}</div>
      <div class="lbl">High/Critical Pushed to Risk Register</div>
    </div>
    <div class="stat-mini" style="border:1px solid var(--green)">
      <div class="big" style="color:var(--green)">{stats.get('skipped',0)}</div>
      <div class="lbl">Low/Medium Filtered (Below Appetite)</div>
    </div>
  </div>
  <p style="margin-top:14px;font-size:12px;color:var(--muted)">
    Risks exported to <code style="color:var(--accent)">data/eramba_import.csv</code>
    using Eramba's official import template schema. Import-ready file contains all 20 columns
    including asset linkage, threat tags, vulnerability tags, ISO 27001 control mapping,
    treatment strategy, and residual risk scores.
  </p>
</div>

<!-- FOOTER -->
<div class="footer">
  <p><strong style="color:var(--accent)">SecureGRC</strong>
    &mdash; ISO 27001 Compliance &amp; Vulnerability Intelligence Platform</p>
  <p style="margin-top:5px">
    BRS = (CVSS &times; Asset_Criticality &times; Exposure_Factor) &divide; 5
    &nbsp;&bull;&nbsp; Exposure: 1.0 Internet-facing &bull; 0.7 Internal &bull; 0.4 Air-gapped
    &nbsp;&bull;&nbsp; Critical&ge;8 &bull; High&ge;6 &bull; Medium&ge;4 &bull; Low&lt;4
  </p>
  <p style="margin-top:5px">
    Generated: {REPORT_DT} &nbsp;&bull;&nbsp; Framework: ISO 27001:2022 Annex A
    &nbsp;&bull;&nbsp; CVE Source: NIST NVD &nbsp;&bull;&nbsp; GRC Platform: Eramba Community v3.3
    &nbsp;&bull;&nbsp; AI: Ollama / mistral
  </p>
</div>

</div>
</body>
</html>"""


def main():
    log.info("=" * 55)
    log.info("SecureGRC -- GRC Dashboard Generator")
    log.info(f"Timestamp: {REPORT_DT}")
    log.info("=" * 55)

    df         = load_risks()
    summary    = load_summary()
    compliance = calc_compliance()

    log.info(f"Compliance score : {compliance['score']}% ({compliance['rating']})")
    log.info(f"Overall risk     : {risk_rating(df)}")
    log.info(f"CVEs loaded      : {len(df)}")

    log.info("Generating charts...")
    charts = {
        "donut":    chart_donut(compliance),
        "domain":   chart_domain(domain_scores()),
        "severity": chart_severity(df),
        "trend":    chart_trend(),
        "heatmap":  file_to_b64(HEATMAP_INPUT),
        "barchart": file_to_b64(BARCHART_INPUT),
    }
    log.info("All 6 charts generated")

    log.info("Building HTML report...")
    html    = build_html(df, summary, compliance, charts)
    with open(HTML_OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = round(os.path.getsize(HTML_OUTPUT) / 1024, 1)

    print(f"\n{'='*60}")
    print("  SECUREGRC -- M8 DASHBOARD COMPLETE")
    print(f"{'='*60}")
    print(f"  File      : {HTML_OUTPUT}")
    print(f"  Size      : {size_kb} KB (fully self-contained)")
    print(f"  Compliance: {compliance['score']}% ({compliance['rating']})")
    print(f"  Risk      : {risk_rating(df)}")
    print(f"\n  Open with :")
    print(f"    start {HTML_OUTPUT}")
    print(f"\n  Sections  :")
    print(f"    + Header with risk rating badges")
    print(f"    + 4 key metric cards")
    print(f"    + Executive summary")
    print(f"    + Control implementation donut chart")
    print(f"    + Compliance by ISO domain (bars + chart)")
    print(f"    + Risk severity distribution")
    print(f"    + ISO 27001 heat map (embedded)")
    print(f"    + Top 10 CVEs by BRS table")
    print(f"    + BRS distribution chart (embedded)")
    print(f"    + 20-control implementation register")
    print(f"    + 6-month compliance trend chart")
    print(f"    + Eramba GRC platform stats")
    print(f"    + Footer with BRS methodology")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()