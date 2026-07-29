# SecureGRC — ISO 27001 Compliance & Vulnerability Intelligence Platform

> A production-grade GRC automation platform built entirely on free, open-source tools.
> Combines real CVE intelligence, business risk scoring, ISO 27001 control mapping,
> AI-powered risk narratives, and a self-contained compliance dashboard.


---

## What is SecureGRC?

SecureGRC is a self-directed GRC engineering project simulating a real
ISO 27001 compliance programme for a fictional fintech company (AcmeCorp).
It is built entirely with free, open-source tools and runs locally on Windows 11.

The project demonstrates that GRC is not a spreadsheet exercise —
it is an engineering discipline that can be automated, integrated,
and made intelligent with modern tooling.


---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureGRC Pipeline (main.py)                │
│                                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │vuln_puller  │──▶│ risk_scorer │──▶│  eramba_updater.py  │   │
│  │    .py      │   │    .py      │   │                     │   │
│  │ NVD CVE API │   │ BRS Formula │   │ Eramba import CSV   │   │
│  │ 7 Assets    │   │ Heat Map    │   │ Official template   │   │
│  │ CVSS Scores │   │ BRS Charts  │   │ 20-column schema    │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
│         │                │                      │               │
│         └────────────────▼──────────────────────┘               │
│                  data/scored_risks.csv                           │
│                          │                                      │
│           ┌──────────────┴──────────────┐                       │
│           ▼                             ▼                       │
│  ┌─────────────────┐         ┌─────────────────────┐            │
│  │narrative_genera │         │    dashboard.py      │            │
│  │    tor.py       │         │                     │            │
│  │ Ollama/mistral  │         │ HTML Compliance     │            │
│  │ Exec Summary    │         │ Dashboard           │            │
│  │ Tech Briefing   │         │ 13 Sections         │            │
│  └─────────────────┘         └─────────────────────┘            │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Eramba Community v3.3 (Docker)               │  │
│  │   18 Assets · 10 Policies · 20 Controls · 10 Risks       │  │
│  │         MySQL 8.4 · Redis 7.4 · Docker Compose           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Tool | Purpose |
|---|---|---|
| GRC Platform | Eramba Community v3.3 (Docker) | Asset inventory, ISO 27001 controls, risk register |
| Containerisation | Docker Desktop 29.5 + Compose v5 | Local deployment |
| Vulnerability Intel | NIST NVD CVE REST API | Real CVE data for 7 assets |
| Risk Scoring | Python + pandas + matplotlib | BRS formula + visualisation |
| GRC Integration | Python CSV export | Eramba official import template |
| AI Narrative | Ollama + mistral (local LLM) | Executive and technical reports |
| Dashboard | Python + matplotlib + HTML/CSS | Self-contained portfolio report |
| Version Control | Git + GitHub | Full project history |

**Total cost: $0 — entirely free and open source.**

---

## Project Structure

```
secureGRC/
├── automation/
│   ├── vuln_puller.py          # M4: NVD CVE API + BRS scoring engine
│   ├── risk_scorer.py          # M5: pandas analysis + heat map + charts
│   ├── eramba_updater.py       # M6: Eramba official import CSV generator
│   ├── narrative_generator.py  # M7: Ollama AI executive + technical reports
│   └── dashboard.py            # M8: Self-contained HTML compliance dashboard
├── data/
│   ├── scored_risks.csv        # BRS-scored CVE records (auto-generated)
│   ├── eramba_import.csv       # Eramba 20-column import format
│   ├── raw_vulns_*.json        # Raw NVD API responses
│   └── integration_summary.json
├── docs/
│   ├── methodology.md          # BRS formula + design decisions
│   ├── iso27001_control_mapping.md
│   ├── M1_gap_analysis.md
│   ├── control_asset_mapping.md
│   └── known-limitations.md
├── prompts/
│   ├── executive_prompt.txt    # LLM prompt: CISO/board report
│   └── technical_prompt.txt    # LLM prompt: security team report
├── reports/
│   ├── grc_dashboard_report.html   # Portfolio compliance dashboard
│   ├── executive_risk_summary.md   # AI executive report
│   ├── technical_briefing.md       # AI technical report
│   ├── risk_heatmap.png
│   └── brs_distribution.png
├── platform/eramba/            # Docker Compose + Eramba config
├── .env.example
├── main.py                     # Pipeline orchestrator
└── README.md
```

---

## Quick Start

### Prerequisites

- Windows 11 (or Linux/macOS)
- Python 3.10+
- Docker Desktop
- Git
- Ollama with mistral (`ollama pull mistral`)

### Setup

```powershell
# Clone
git clone https://github.com/Shreypatel46/secureGRC.git
cd secureGRC

# Virtual environment
python -m venv venv
venv\Scripts\activate

# Dependencies
pip install requests pandas matplotlib python-dotenv

# Start Eramba
cd platform\eramba
docker compose -f docker-compose.simple-install.yml up -d
cd ..\..

# Configure .env
copy .env.example .env
# Edit .env with your Eramba credentials
```

### Run

```powershell
# Full pipeline
python main.py

# Individual steps
python main.py --scan-only       # NVD scan + BRS scoring
python main.py --update-only     # Eramba import CSV only
python main.py --narrative-only  # AI reports only
```

### View outputs

```powershell
start reports\grc_dashboard_report.html
code reports\executive_risk_summary.md
```

---

## The Business Risk Score Formula

```
BRS = (CVSS_Base × Asset_Criticality × Exposure_Factor) / 5
```

| Parameter | Range | Description |
|---|---|---|
| CVSS_Base | 0–10 | NVD vulnerability severity score |
| Asset_Criticality | 1–5 | Business importance from Eramba asset register |
| Exposure_Factor | 0.4–1.0 | 1.0=internet-facing · 0.7=internal · 0.4=air-gapped |
| ÷5 normalisation | — | Scales result to 0–10 |

**Classifications:** Critical ≥8 · High ≥6 · Medium ≥4 · Low <4

A CVSS 9.8 CVE on an air-gapped low-criticality system (BRS=1.57)
is less urgent than a CVSS 7.0 CVE on an internet-facing payment
server (BRS=7.0). BRS adds business context that raw CVSS lacks.

---

## ISO 27001 Coverage

| Domain | Controls Assessed | Implemented | Partial | Not Implemented |
|---|---|---|---|---|
| A.5 Organizational | 3 | 1 | 1 | 1 |
| A.6 People | 2 | 0 | 1 | 1 |
| A.7 Physical | 2 | 1 | 1 | 0 |
| A.8 Technological | 13 | 3 | 5 | 5 |
| **Total** | **20** | **5** | **8** | **7** |

Overall compliance score: **45%** — realistic for a fintech startup
beginning its ISO 27001 journey.

---

## Pipeline Outputs

| File | Script | Description |
|---|---|---|
| `data/scored_risks.csv` | vuln_puller.py | CVEs with BRS scores |
| `reports/risk_heatmap.png` | risk_scorer.py | ISO 27001 5×5 matrix |
| `reports/brs_distribution.png` | risk_scorer.py | BRS distribution |
| `data/eramba_import.csv` | eramba_updater.py | Eramba import format |
| `reports/executive_risk_summary.md` | narrative_generator.py | Board report |
| `reports/technical_briefing.md` | narrative_generator.py | Security team report |
| `reports/grc_dashboard_report.html` | dashboard.py | Portfolio dashboard |

---

## Known Limitations

See [docs/known-limitations.md](docs/known-limitations.md)

- Eramba Worker cron does not run on Windows Docker Desktop (upstream issue)
- NVD API: 5 req/30s without key — handled with `time.sleep(7)`
- Ollama narrative speed depends on CPU (30–90s per report)

---

## What This Project Demonstrates

| Skill | Evidence |
|---|---|
| GRC framework knowledge | ISO 27001 Annex A mapping, gap analysis, risk register |
| Risk quantification | Custom BRS formula contextualising CVEs for business |
| Python automation | 5 production scripts with logging, error handling, CLI modes |
| REST API integration | NIST NVD API with pagination and rate limit handling |
| Docker / containerisation | Eramba + MySQL + Redis via Docker Compose |
| AI / LLM integration | Local Ollama generating structured GRC reports |
| Data visualisation | matplotlib heat maps, distribution charts, trend analysis |
| Technical writing | Architecture docs, methodology, control mapping |

---

## Author

**Shrey Patel**
GitHub: [@Shreypatel46](https://github.com/Shreypatel46)
Project: [github.com/Shreypatel46/secureGRC](https://github.com/Shreypatel46/secureGRC)

---

*$0 cost. 100% open source. Runs entirely on Windows 11.*