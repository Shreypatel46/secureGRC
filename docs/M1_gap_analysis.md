# AcmeCorp ISO 27001 Gap Analysis Report
**Date:** 2026-07-23  
**Assessor:** Ankit Patel (CISO)  
**Scope:** ISO 27001:2022 Annex A — 20 controls assessed

## Compliance Summary

| Result | Count | Percentage |
|---|---|---|
| Pass | 4 | 40% |
| Fail | 8 | 60% |
| **Overall Score** | | **40%** |

## Controls Passing
- A.5.15 Access Control
- A.7.1 Physical Security Perimeters  
- A.8.5 Secure Authentication
- A.8.7 Protection Against Malware
- A.8.24 Use of Cryptography

## Critical Gaps (Fail)
- A.5.23 Cloud Services — No cloud security policy
- A.6.8 Incident Reporting — No formal mechanism
- A.8.2 Privileged Access — Shared admin credentials in use
- A.8.8 Vulnerability Management — No scanning tool
- A.8.9 Configuration Management — No baseline documented
- A.8.12 Data Leakage Prevention — No DLP deployed
- A.8.16 Monitoring — No SIEM deployed

## Top 3 Priority Remediations
1. **A.8.2** — Implement PAM solution, eliminate shared admin accounts (High risk)
2. **A.8.8** — Deploy vulnerability scanner, establish patch SLA (High risk)  
3. **A.8.16** — Deploy SIEM with alerting (High risk)

## Next Review Date
2027-01-01