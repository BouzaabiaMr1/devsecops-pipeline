# Automated DevSecOps Pipeline & Vulnerability Management System

> **Projet de Fin d'Études** — Automated security pipeline integrating SAST, DAST, SCA,
> container scanning, and centralized vulnerability management with DefectDojo.

---

## Architecture

```
GitHub Push/PR
      │
      ▼
GitHub Actions Pipeline
  ├── [SAST]   Bandit + Semgrep       → Python source analysis
  ├── [SAST]   TruffleHog             → Secret scanning
  ├── [SCA]    pip-audit              → Dependency CVEs
  ├── [IMAGE]  Trivy                  → Container vulnerabilities
  └── [DAST]   OWASP ZAP              → Runtime web scanning
                    │
                    ▼
              DefectDojo API
                    │
                    ▼
          Centralized Dashboard
         (findings, SLA, reports)
```

## Project Structure

```
devsecops-pipeline/
├── .github/workflows/
│   └── devsecops-pipeline.yml   # Main CI/CD pipeline
├── .zap/
│   └── rules.tsv                # ZAP false-positive suppression
├── app/
│   ├── app.py                   # VulnFlask (intentionally vulnerable target)
│   ├── requirements.txt
│   └── Dockerfile
├── scripts/
│   ├── setup.sh                 # One-time local setup
│   └── defectdojo/
│       └── defectdojo_api.py    # DefectDojo REST API integration
├── k8s/                         # Kubernetes manifests (Phase 7)
├── docs/                        # Architecture diagrams
└── README.md
```

## Quick Start

### Prerequisites
- Docker running
- DefectDojo at `http://127.0.0.1:8080`
- GitHub account

### Step 1 — Run setup script
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Step 2 — Initialize git and push
```bash
git init
git add .
git commit -m "feat: initial DevSecOps pipeline setup"
git remote add origin https://github.com/YOUR_USERNAME/devsecops-pipeline.git
git push -u origin main
```

### Step 3 — Add GitHub Secrets
Go to: `Settings → Secrets and variables → Actions`

| Secret | Value |
|--------|-------|
| `DOJO_URL` | Your DefectDojo URL (use ngrok for local) |
| `DOJO_API_KEY` | From setup.sh output |

### Step 4 — Trigger the pipeline
Push any change — the pipeline starts automatically.

## Tools Used

| Tool | Purpose | Phase |
|------|---------|-------|
| GitHub Actions | CI/CD orchestration | All |
| Bandit | Python SAST | 2 |
| Semgrep | Multi-language SAST | 2 |
| TruffleHog | Secret scanning | 2 |
| pip-audit | Dependency SCA | 3 |
| Trivy | Container scanning | 3 |
| OWASP ZAP | DAST | 4 |
| DefectDojo | Vulnerability management | All |
| Kubernetes | Container orchestration | 7 |

## Vulnerabilities in VulnFlask (intentional)

| Vulnerability | Type | Location |
|--------------|------|----------|
| SQL Injection | OWASP A03 | `/login` |
| Reflected XSS | OWASP A03 | `/search` |
| Command Injection | OWASP A03 | `/ping` |
| Weak hashing (MD5) | OWASP A02 | `/register` |
| Hardcoded secret | OWASP A07 | `app.py:11` |
| Debug mode enabled | OWASP A05 | `app.py:last line` |
| Running as root | OWASP A05 | `Dockerfile` |

---

*This project is for educational purposes only. The VulnFlask app must never be deployed in production.*
