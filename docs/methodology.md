# SecureGRC — Methodology & Design Decisions

**Author:** Shrey Patel
**Framework:** ISO 27001:2022
**Date:** 2026-07-29

---

## 1. Project Philosophy

Most GRC learning happens through certification courses that teach
frameworks theoretically. SecureGRC takes the opposite approach:
every concept is implemented as working software.

The guiding principle: **if you can automate it, you understand it.**

---

## 2. The Business Risk Score (BRS) Formula

### Formula

```
BRS = (CVSS_Base × Asset_Criticality × Exposure_Factor) / 5
```

### Rationale

**Why not use CVSS directly?**

CVSS (Common Vulnerability Scoring System) scores the technical
severity of a vulnerability in isolation. It does not consider:
- How critical the affected system is to the business
- Whether the system is reachable from the internet
- The organisation's own risk appetite

A CVSS 9.8 vulnerability on a developer's test laptop is not the
same business risk as a CVSS 9.8 on a payment processing server.

**Why multiply rather than add?**

Multiplication creates compounding risk — a high-severity CVE on
a critical internet-facing asset produces a dramatically higher BRS
than the same CVE on an internal low-criticality system. This
reflects real-world risk compounding.

**Why divide by 5?**

Max raw score = 10 (CVSS) × 5 (criticality) × 1.0 (exposure) = 50.
Dividing by 5 normalises the result to a 0–10 scale that matches
the CVSS scale people are already familiar with.

### Parameter Definitions

**CVSS_Base (0–10)**
- Source: NIST NVD CVE database, CVSSv3.1 preferred, v2 fallback
- Represents: Technical severity of the vulnerability itself

**Asset_Criticality (1–5)**
- Source: Eramba asset inventory, assigned during M1
- 5 = Business-critical (payment processing, customer PII)
- 3 = Important but not critical (developer endpoints)
- 2 = Low business impact (internal HR portal)
- 1 = Negligible business impact

**Exposure_Factor**
- 1.0 = Internet-facing (directly reachable by external attackers)
- 0.7 = Internal network (reachable by insiders or lateral movement)
- 0.4 = Air-gapped or highly isolated systems

### Classification Thresholds

| BRS | Classification | Action |
|---|---|---|
| 8.0–10.0 | Critical | Immediate remediation — escalate to CISO |
| 6.0–7.9 | High | Remediate within 7 days |
| 4.0–5.9 | Medium | Remediate within 30 days |
| 0–3.9 | Low | Accept or schedule within 90 days |

Thresholds align with our Eramba Risk Appetite configuration
(threshold value: 15, equivalent to BRS 6.0 on normalised scale).

### Example Calculations

| CVE | Asset | CVSS | Criticality | Exposure | BRS | Class |
|---|---|---|---|---|---|---|
| CVE-2024-XXXX | AcmePay Web App | 9.8 | 5 | 1.0 | 9.8 | Critical |
| CVE-2024-XXXX | Internal HR Portal | 9.8 | 2 | 0.7 | 2.74 | Low |
| CVE-2024-YYYY | Customer PII DB | 7.5 | 5 | 0.4 | 3.0 | Low |
| CVE-2024-YYYY | Payment Gateway | 7.5 | 5 | 1.0 | 7.5 | High |

---

## 3. ISO 27001 Control Selection Rationale

### Why ISO 27001:2022?

- Globally recognised information security standard
- Required for fintech companies handling payment data
- Annex A provides a concrete, auditable control set
- Maps directly to CVSS vulnerability categories

### Control Domain Selection

20 controls were selected from 4 Annex A domains:

**A.5 Organizational (3 controls)**
Selected to cover governance foundation: policies, access control
philosophy, and cloud services — the three areas AcmeCorp had
the most gap.

**A.6 People (2 controls)**
Awareness training and incident reporting — the two human-layer
controls most directly affected by phishing and social engineering.

**A.7 Physical (2 controls)**
Physical perimeters and monitoring — included because AcmeCorp
has physical office infrastructure with a server room.

**A.8 Technological (13 controls)**
The largest domain — covers the technical controls that directly
correspond to the CVE vulnerabilities identified in the NVD scan.
Includes patch management, access restriction, logging, monitoring,
cryptography, and secure coding.

### Control-to-CVE Mapping Logic

Controls were linked to assets using a keyword-to-clause mapping:

| CVE Type / Asset Software | ISO 27001 Control |
|---|---|
| Web server CVEs (apache/nginx) | A.8.8 Vulnerability Management |
| Authentication CVEs (openssl) | A.8.5 Secure Authentication |
| Database CVEs (mysql) | A.8.3 Information Access Restriction |
| Cloud CVEs (amazon/aws) | A.5.23 Cloud Services |
| Endpoint CVEs (python/php) | A.8.1 User Endpoint Devices |

This mapping is implemented in `automation/eramba_updater.py`
as the `CONTROL_MAP` dictionary.

---

## 4. Asset Classification Rationale

### AcmeCorp Asset Inventory

AcmeCorp is a 200-person fintech company processing payments and
storing customer PII. Asset criticality was assigned based on:

1. **Business process dependency** — would AcmeCorp stop trading if this asset failed?
2. **Data sensitivity** — does this asset store or process Confidential data?
3. **Regulatory exposure** — is this asset in scope for PCI-DSS or DPDP Act?

### Exposure Factor Assignment

| Asset | Exposure | Justification |
|---|---|---|
| AcmePay Web App | 1.0 | Public-facing, directly reachable by anyone |
| Payment Gateway API | 1.0 | Internet-facing API endpoint |
| AWS Production | 1.0 | Cloud infrastructure, internet-accessible |
| Authentication Server | 0.7 | Internal, but reachable via web app requests |
| Developer Laptops | 0.7 | Internal network, reachable via phishing |
| Internal HR Portal | 0.7 | Internal intranet only |
| Customer PII Database | 0.4 | No direct network exposure, accessed via app layer only |

---

## 5. AI Narrative Design Decisions

### Why Ollama + mistral over cloud LLM?

- **Cost:** $0 vs. API fees per token
- **Privacy:** Risk data never leaves the machine
- **Offline:** Works without internet after model download
- **Reproducibility:** Same model version, same results

### Prompt Engineering Approach

Two distinct prompts were designed for two audiences:

**Executive prompt** (CISO/board):
- Plain English, no jargon
- Business impact framing
- Investment-focused recommendations
- ISO 27001 clause references kept brief

**Technical prompt** (security team):
- CVE IDs and CVSS scores included
- Specific remediation commands
- Attack chain analysis
- 30-60-90 day roadmap

Temperature was set to 0.3 (low) to produce factual, consistent
output rather than creative variation — appropriate for compliance
documents.

---

## 6. Design Decisions Log

| Decision | Alternative considered | Why we chose this |
|---|---|---|
| NVD API over OpenVAS | Running OpenVAS locally | NVD is more realistic for GRC analysts; OpenVAS is complex on Windows |
| HTML dashboard over PDF | weasyprint PDF | Self-contained HTML works everywhere; PDF requires Linux dependencies |
| CSV import over Eramba API | Direct REST API write | Asset Risk API write is Enterprise-only in Community Edition |
| Eramba over custom GRC app | Building from scratch | Real GRC platforms have features no scratch build would replicate in scope |
| mistral over llama3 | llama3, phi3 | mistral already downloaded; strong at structured text tasks |
| Basic Auth over API tokens | OAuth flow | Eramba Community uses Basic Auth; no token endpoint available |

---

*This document reflects decisions made during the SecureGRC project build, July 2026.*