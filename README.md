# Detection-as-Code SIEM

Automated detection rule deployment pipeline for **IBM QRadar** and **Splunk** using GitHub Actions and REST APIs.

## Overview

This repository implements a **Detection-as-Code** workflow — all detection rules are written and maintained in GitHub, never edited directly in the SIEM. Every push to `main` automatically deploys updated rules to QRadar and Splunk via their REST APIs.

## Repository Structure
Detection-as-Code-SIEM/

├── .github/

│   └── workflows/

│       ├── deploy-qradar-rules.yml    # QRadar CI/CD pipeline

│       └── deploy-splunk-rules.yml    # Splunk CI/CD pipeline

├── qradar-rules/                      # IBM QRadar detection rules (JSON)

├── splunk-rules/                      # Splunk detection rules (YAML)

├── scripts/

│   ├── push_rules_to_qradar.py        # QRadar deployment script

│   └── push_rules_to_splunk.py        # Splunk deployment script

└── requirements.txt

## Detection Rules

### IBM QRadar (12 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| LFI Detection | 7 | Detects Local File Inclusion attacks via path traversal |
| RCE Detection | 8 | Detects Remote Code Execution attempts |
| Web Admin Brute Force | 7 | Detects brute force attacks on admin panels |
| IDOR Detection | 7 | Detects Insecure Direct Object Reference exploitation |
| Linux Privilege Escalation | 8 | Detects privilege escalation attempts on Linux |
| Malicious PowerShell | 8 | Detects encoded/obfuscated PowerShell execution |
| NoSQL Injection | 7 | Detects NoSQL injection attempts |
| Ransomware Activity | 9 | Detects ransomware file encryption indicators |
| SQL Injection | 8 | Detects SQL injection attacks |
| SSH Brute Force | 7 | Detects SSH brute force login attempts |
| SSRF Detection | 8 | Detects Server-Side Request Forgery attacks |
| XSS Detection | 7 | Detects Cross-Site Scripting injection attempts |

### Splunk (15 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| LFI Detection | High | Path traversal and local file inclusion |
| RCE Detection | Critical | Remote code execution patterns |
| SQL Injection | High | SQL injection in HTTP requests |
| XSS Detection | Medium | Cross-site scripting attempts |
| SSH Brute Force | High | Multiple failed SSH authentications |
| Admin Brute Force | High | Brute force on administrative panels |
| SSRF Detection | High | Server-side request forgery |
| IDOR Detection | Medium | Insecure direct object references |
| Linux Privilege Escalation | High | Sudo and root escalation attempts |
| Malicious PowerShell | High | Obfuscated PowerShell commands |
| NoSQL Injection | High | MongoDB/NoSQL injection patterns |
| Ransomware Activity | Critical | File encryption and ransomware indicators |
| DNS Tunneling | High | Data exfiltration via DNS queries |
| Suspicious User Agent | Medium | Malicious or scanning user agents |
| Log4Shell | Critical | CVE-2021-44228 exploitation attempts |

## CI/CD Pipeline

Developer pushes rule changes to GitHub

↓

GitHub Actions triggers

↓

┌──────────────┐

│   AQL/SPL    │  ← Validates query syntax

│  Validation  │

└──────────────┘

↓

┌──────────────┐

│  Deploy to   │  ← Pushes via REST API

│  QRadar &    │

│   Splunk     │

└──────────────┘

↓

Deployment Summary
## How It Works

1. Detection rules are written as JSON (QRadar) or YAML (Splunk) files
2. On every `push` to `main`, GitHub Actions runs the deployment pipeline
3. Scripts validate AQL/SPL query syntax against live SIEM instances
4. Rules are automatically synced to QRadar and Splunk via REST APIs
5. Deployment state is tracked to avoid redundant updates

## Configuration

Required GitHub Secrets:

| Secret | Description |
|--------|-------------|
| `QRADAR_HOST` | IBM QRadar instance URL |
| `QRADAR_TOKEN` | QRadar API authentication token |
| `SPLUNK_HOST` | Splunk instance URL |
| `SPLUNK_TOKEN` | Splunk API authentication token |

## Rule Format

### QRadar Rule (JSON)
```json
{
  "name": "QRadar - SQL Injection Detection",
  "description": "Detects SQL injection patterns in HTTP requests",
  "aql_query": "SELECT sourceip, destinationip FROM events WHERE UTF8(payload) LIKE '%UNION SELECT%' LAST 5 MINUTES",
  "severity": 8,
  "type": "Custom Rule"
}
```

### Splunk Rule (YAML)
```yaml
name: Splunk - SQL Injection Detection
description: Detects SQL injection patterns in HTTP requests
search: index=* sourcetype=access_combined | search uri="*UNION*SELECT*"
severity: high
```

## References

- [SIGMA Rules](https://github.com/SigmaHQ/sigma) — Detection rule standard
- [IBM QRadar REST API](https://www.ibm.com/docs/en/qradar-siem)
- [Splunk REST API](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
