# ============================================================
#  DevSecOps Pipeline — GitHub Actions
#  Runs on every push/PR to main branch
#
#  Stages:
#    1. DefectDojo setup (product + engagement)
#    2. SAST — Bandit (Python)
#    3. SAST — Semgrep
#    4. Secret scanning — TruffleHog
#    5. Dependency scanning — Safety / pip-audit
#    6. Container build + Trivy image scan
#    7. DAST — OWASP ZAP (baseline)
#    8. Upload all results to DefectDojo
# ============================================================

name: DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  workflow_dispatch:   # allow manual trigger from GitHub UI

env:
  DOJO_URL:     ${{ secrets.DOJO_URL }}
  DOJO_API_KEY: ${{ secrets.DOJO_API_KEY }}
  DOJO_PRODUCT: "VulnFlask"
  IMAGE_NAME:   "vulnflask"
  IMAGE_TAG:    ${{ github.sha }}

jobs:
  # ============================================================
  #  JOB 0 — Setup DefectDojo product & engagement
  # ============================================================
  dojo-setup:
    name: "DefectDojo — Setup"
    runs-on: ubuntu-latest
    outputs:
      engagement_id: ${{ steps.setup.outputs.engagement_id }}
      product_id:    ${{ steps.setup.outputs.product_id }}

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install requests
        run: pip install requests

      - name: Create product & engagement in DefectDojo
        id: setup
        run: |
          python scripts/defectdojo/defectdojo_api.py --action setup
          source results/dojo_ids.env
          echo "product_id=${DOJO_PRODUCT_ID}"    >> $GITHUB_OUTPUT
          echo "engagement_id=${DOJO_ENGAGEMENT_ID}" >> $GITHUB_OUTPUT

      - name: Upload IDs artifact
        uses: actions/upload-artifact@v4
        with:
          name: dojo-ids
          path: results/dojo_ids.env

  # ============================================================
  #  JOB 1 — SAST: Bandit (Python source code)
  # ============================================================
  sast-bandit:
    name: "SAST — Bandit"
    runs-on: ubuntu-latest
    needs: dojo-setup

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Bandit
        run: pip install bandit requests

      - name: Run Bandit scan
        run: |
          mkdir -p results
          bandit -r app/ \
            -f json \
            -o results/bandit.json \
            --severity-level low \
            --confidence-level low || true   # don't fail pipeline on findings

      - name: Print Bandit summary
        run: |
          if [ -f results/bandit.json ]; then
            python -c "
          import json, sys
          data = json.load(open('results/bandit.json'))
          metrics = data.get('metrics',{}).get('_totals',{})
          print('=== Bandit Summary ===')
          for sev in ['HIGH','MEDIUM','LOW']:
              key = f'SEVERITY.{sev}'
              print(f'  {sev}: {metrics.get(key,0)} issues')
            "
          fi

      - name: Import Bandit results to DefectDojo
        run: |
          pip install requests
          python scripts/defectdojo/defectdojo_api.py \
            --action import \
            --scan-type bandit \
            --file results/bandit.json \
            --engagement-id ${{ needs.dojo-setup.outputs.engagement_id }}

      - name: Upload Bandit artifact
        uses: actions/upload-artifact@v4
        with:
          name: bandit-results
          path: results/bandit.json

  # ============================================================
  #  JOB 2 — SAST: Semgrep
  # ============================================================
  sast-semgrep:
    name: "SAST — Semgrep"
    runs-on: ubuntu-latest
    needs: dojo-setup

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Semgrep
        run: pip install semgrep requests

      - name: Run Semgrep scan
        run: |
          mkdir -p results
          semgrep scan \
            --config=auto \
            --json \
            --output results/semgrep.json \
            app/ || true

      - name: Import Semgrep results to DefectDojo
        run: |
          python scripts/defectdojo/defectdojo_api.py \
            --action import \
            --scan-type semgrep \
            --file results/semgrep.json \
            --engagement-id ${{ needs.dojo-setup.outputs.engagement_id }}

      - name: Upload Semgrep artifact
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-results
          path: results/semgrep.json

  # ============================================================
  #  JOB 3 — Secrets scanning: TruffleHog
  # ============================================================
  secrets-scan:
    name: "Secrets — TruffleHog"
    runs-on: ubuntu-latest
    needs: dojo-setup

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history for TruffleHog

      - name: Run TruffleHog
        run: |
          mkdir -p results
          docker run --rm             -v "$PWD:/pwd"             trufflesecurity/trufflehog:latest             filesystem /pwd             --json             --no-update             > results/trufflehog.json 2>/dev/null || true
          echo "TruffleHog scan complete"
          cat results/trufflehog.json | head -5 || echo "No findings"

      - name: Install requests & import to DefectDojo
        run: |
          pip install requests
          if [ -f results/trufflehog.json ]; then
            python scripts/defectdojo/defectdojo_api.py \
              --action import \
              --scan-type trufflehog \
              --file results/trufflehog.json \
              --engagement-id ${{ needs.dojo-setup.outputs.engagement_id }}
          else
            echo "No secrets file generated — skipping import"
          fi

  # ============================================================
  #  JOB 4 — SCA: pip-audit (dependency vulnerabilities)
  # ============================================================
  sca-dependencies:
    name: "SCA — pip-audit"
    runs-on: ubuntu-latest
    needs: dojo-setup

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install pip-audit and requests
        run: pip install pip-audit requests

      - name: Run pip-audit
        run: |
          mkdir -p results
          pip-audit \
            -r app/requirements.txt \
            --format json \
            --output results/pip-audit.json || true

      - name: Print SCA summary
        run: |
          if [ -f results/pip-audit.json ]; then
            python -c "
          import json
          data = json.load(open('results/pip-audit.json'))
          vulns = data.get('vulnerabilities', [])
          print(f'=== pip-audit: {len(vulns)} vulnerable packages ===')
          for v in vulns:
              print(f'  {v[\"name\"]} {v[\"version\"]} → {len(v[\"vulns\"])} CVE(s)')
            "
          fi

      - name: Upload SCA artifact
        uses: actions/upload-artifact@v4
        with:
          name: pip-audit-results
          path: results/pip-audit.json

  # ============================================================
  #  JOB 5 — Container scan: Trivy
  # ============================================================
  container-scan:
    name: "Container — Trivy"
    runs-on: ubuntu-latest
    needs: dojo-setup

    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: |
          docker build -t ${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }} app/

      - name: Run Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: "${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }}"
          format:    "json"
          output:    "results/trivy.json"
          severity:  "CRITICAL,HIGH,MEDIUM,LOW"
          exit-code: "0"   # don't fail pipeline

      - name: Install requests & import to DefectDojo
        run: |
          pip install requests
          python scripts/defectdojo/defectdojo_api.py \
            --action import \
            --scan-type trivy \
            --file results/trivy.json \
            --engagement-id ${{ needs.dojo-setup.outputs.engagement_id }}

      - name: Upload Trivy artifact
        uses: actions/upload-artifact@v4
        with:
          name: trivy-results
          path: results/trivy.json

  # ============================================================
  #  JOB 6 — DAST: OWASP ZAP baseline scan
  # ============================================================
  dast-zap:
    name: "DAST — OWASP ZAP"
    runs-on: ubuntu-latest
    needs: [dojo-setup, container-scan]

    steps:
      - uses: actions/checkout@v4

      - name: Start VulnFlask in Docker
        run: |
          docker build -t ${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }} app/
          docker run -d \
            --name vulnflask \
            -p 5000:5000 \
            ${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }}
          sleep 5
          curl -s http://localhost:5000/health || echo "App may still be starting"

      - name: Run OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.11.0
        with:
          target:       "http://localhost:5000"
          fail_action:  false
          cmd_options:  "-J results/zap.json -r results/zap.html"
          rules_file_name: ".zap/rules.tsv"

      - name: Install requests & import ZAP to DefectDojo
        run: |
          pip install requests
          if [ -f results/zap.json ]; then
            python scripts/defectdojo/defectdojo_api.py \
              --action import \
              --scan-type zap \
              --file results/zap.json \
              --engagement-id ${{ needs.dojo-setup.outputs.engagement_id }}
          fi

      - name: Upload ZAP artifacts
        uses: actions/upload-artifact@v4
        with:
          name: zap-results
          path: |
            results/zap.json
            results/zap.html

      - name: Stop VulnFlask
        if: always()
        run: docker stop vulnflask && docker rm vulnflask

  # ============================================================
  #  JOB 7 — Pipeline summary
  # ============================================================
  pipeline-summary:
    name: "Pipeline — Summary"
    runs-on: ubuntu-latest
    needs: [sast-bandit, sast-semgrep, secrets-scan, sca-dependencies, container-scan, dast-zap]
    if: always()

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install requests
        run: pip install requests

      - name: Print findings summary from DefectDojo
        run: |
          python scripts/defectdojo/defectdojo_api.py \
            --action findings \
            --product-id ${{ needs.dojo-setup.outputs.product_id }}

      - name: Post summary to GitHub Step Summary
        run: |
          echo "## DevSecOps Pipeline Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Scan | Status |" >> $GITHUB_STEP_SUMMARY
          echo "|------|--------|" >> $GITHUB_STEP_SUMMARY
          echo "| SAST (Bandit)    | ${{ needs.sast-bandit.result }}    |" >> $GITHUB_STEP_SUMMARY
          echo "| SAST (Semgrep)   | ${{ needs.sast-semgrep.result }}   |" >> $GITHUB_STEP_SUMMARY
          echo "| Secrets (TruffleHog) | ${{ needs.secrets-scan.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| SCA (pip-audit)  | ${{ needs.sca-dependencies.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Container (Trivy)| ${{ needs.container-scan.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| DAST (ZAP)       | ${{ needs.dast-zap.result }}       |" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "View all findings: [${{ env.DOJO_URL }}](${{ env.DOJO_URL }}/dashboard)" >> $GITHUB_STEP_SUMMARY
