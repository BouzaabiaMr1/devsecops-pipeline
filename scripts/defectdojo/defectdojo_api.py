#!/usr/bin/env python3
"""
DefectDojo Integration Script
==============================
Handles: product creation, engagement creation, and scan import
via the DefectDojo REST API v2.
 
Usage:
  python defectdojo_api.py --action setup
  python defectdojo_api.py --action import --scan-type bandit --file results/bandit.json
  python defectdojo_api.py --action import --scan-type trivy  --file results/trivy.json
  python defectdojo_api.py --action import --scan-type zap    --file results/zap.xml
"""
 
import argparse
import json
import os
import sys
import requests
from datetime import date
 
# ------------------------------------------------------------------ #
#  Configuration — override via environment variables in CI
# ------------------------------------------------------------------ #
 
DOJO_URL      = os.getenv("DOJO_URL",      "http://127.0.0.1:8080")
DOJO_API_KEY  = os.getenv("DOJO_API_KEY",  "")          # set in GitHub Secrets
PRODUCT_NAME  = os.getenv("DOJO_PRODUCT",  "VulnFlask")
PRODUCT_TYPE  = os.getenv("DOJO_PRODUCT_TYPE", "1")     # 1 = Research and Development
 
SCAN_TYPE_MAP = {
    "bandit":     "Bandit Scan",
    "semgrep":    "Semgrep JSON Report",
    "trivy":      "Trivy Scan",
    "dependency": "OWASP Dependency Check Scan",
    "zap":        "ZAP Scan",
    "trufflehog": "Trufflehog Scan",
}
 
# ------------------------------------------------------------------ #
#  HTTP helpers
# ------------------------------------------------------------------ #
 
def headers():
    if not DOJO_API_KEY:
        print("[ERROR] DOJO_API_KEY is not set. Export it or pass via env.")
        sys.exit(1)
    return {
        "Authorization": f"Token {DOJO_API_KEY}",
        "Accept":           "application/json",
        "ngrok-skip-browser-warning": "true",
    }
 
 
def get(endpoint):
    r = requests.get(f"{DOJO_URL}/api/v2{endpoint}", headers=headers(), timeout=30)
    r.raise_for_status()
    return r.json()
 
 
def post(endpoint, data=None, files=None):
    h = headers()
    if files:
        # multipart — do NOT set Content-Type (requests sets boundary automatically)
        r = requests.post(f"{DOJO_URL}/api/v2{endpoint}", headers=h, data=data, files=files, timeout=60)
    else:
        h["Content-Type"] = "application/json"
        r = requests.post(f"{DOJO_URL}/api/v2{endpoint}", headers=h, json=data, timeout=30)
    r.raise_for_status()
    return r.json()
 
 
# ------------------------------------------------------------------ #
#  DefectDojo resource helpers
# ------------------------------------------------------------------ #
 
def get_or_create_product(name: str, prod_type_id: int = 1) -> int:
    """Return the product ID, creating it if it doesn't exist."""
    data = get(f"/products/?name={requests.utils.quote(name)}")
    if data["count"] > 0:
        pid = data["results"][0]["id"]
        print(f"[INFO] Product '{name}' already exists (id={pid})")
        return pid
 
    result = post("/products/", {
        "name":         name,
        "description":  "DevSecOps pipeline demo — auto-created by CI",
        "prod_type":    prod_type_id,
    })
    pid = result["id"]
    print(f"[OK] Created product '{name}' (id={pid})")
    return pid
 
 
def get_or_create_engagement(product_id: int, name: str) -> int:
    """Return engagement ID for today's CI run, creating it if needed."""
    today = date.today().isoformat()
    eng_name = f"{name} — {today}"
 
    data = get(f"/engagements/?product={product_id}&name={requests.utils.quote(eng_name)}")
    if data["count"] > 0:
        eid = data["results"][0]["id"]
        print(f"[INFO] Engagement '{eng_name}' already exists (id={eid})")
        return eid
 
    result = post("/engagements/", {
        "name":             eng_name,
        "product":          product_id,
        "target_start":     today,
        "target_end":       today,
        "engagement_type":  "CI/CD",
        "status":           "In Progress",
        "description":      "Automated scan imported by GitHub Actions",
    })
    eid = result["id"]
    print(f"[OK] Created engagement '{eng_name}' (id={eid})")
    return eid
 
 
def import_scan(engagement_id: int, scan_type: str, file_path: str):
    """Upload a scan report file to DefectDojo."""
    if not os.path.exists(file_path):
        print(f"[ERROR] Scan file not found: {file_path}")
        sys.exit(1)
 
    dojo_scan_type = SCAN_TYPE_MAP.get(scan_type)
    if not dojo_scan_type:
        print(f"[ERROR] Unknown scan type '{scan_type}'. Valid: {list(SCAN_TYPE_MAP)}")
        sys.exit(1)
 
    with open(file_path, "rb") as f:
        result = post(
            "/import-scan/",
            data={
                "engagement":      str(engagement_id),
                "scan_type":       dojo_scan_type,
                "minimum_severity": "Low",
                "active":          "true",
                "verified":        "false",
                "close_old_findings": "false",
            },
            files={"file": (os.path.basename(file_path), f)},
        )
 
    count = result.get("test", {})
    print(f"[OK] Imported '{scan_type}' scan → engagement {engagement_id}")
    print(f"     DefectDojo test id: {result.get('test_id', 'N/A')}")
    print(f"     Findings imported:  check DefectDojo dashboard")
    return result
 
 
# ------------------------------------------------------------------ #
#  Actions
# ------------------------------------------------------------------ #
 
def action_setup():
    """Create product + engagement for today's CI run. Prints IDs for downstream steps."""
    pid = get_or_create_product(PRODUCT_NAME, int(PRODUCT_TYPE))
    eid = get_or_create_engagement(pid, "GitHub Actions Pipeline")
 
    # Write IDs to a file so other pipeline steps can read them
    os.makedirs("results", exist_ok=True)
    with open("results/dojo_ids.env", "w") as f:
        f.write(f"DOJO_PRODUCT_ID={pid}\n")
        f.write(f"DOJO_ENGAGEMENT_ID={eid}\n")
 
    print(f"\n[DONE] Setup complete. PRODUCT={pid}, ENGAGEMENT={eid}")
    print("       IDs saved to results/dojo_ids.env")
 
 
def action_import(scan_type: str, file_path: str, engagement_id: int):
    """Import a scan file into an existing engagement."""
    import_scan(engagement_id, scan_type, file_path)
 
 
def action_list_findings(product_id: int):
    """Print a summary of all findings for a product."""
    data = get(f"/findings/?product={product_id}&limit=100")
    print(f"\n{'='*60}")
    print(f"Findings for product {product_id}  (total: {data['count']})")
    print(f"{'='*60}")
    for f in data["results"]:
        sev = f.get("severity", "?")
        title = f.get("title", "?")
        status = "Active" if f.get("active") else "Inactive"
        print(f"  [{sev:8s}] {status:8s}  {title}")
 
 
def action_test_connection():
    """Verify API key and connectivity."""
    try:
        me = get("/users/?limit=1")
        print(f"[OK] Connected to DefectDojo at {DOJO_URL}")
        print(f"     API version: v2")
        print(f"     Users found: {me['count']}")
        return True
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to {DOJO_URL}. Is DefectDojo running?")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP {e.response.status_code} — check your API key.")
        return False
 
 
# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
 
def main():
    parser = argparse.ArgumentParser(description="DefectDojo CI Integration")
    parser.add_argument("--action", required=True,
                        choices=["setup", "import", "findings", "test"],
                        help="Action to perform")
    parser.add_argument("--scan-type", help="Scan type (bandit/semgrep/trivy/dependency/zap/trufflehog)")
    parser.add_argument("--file",      help="Path to scan result file")
    parser.add_argument("--engagement-id", type=int, help="DefectDojo engagement ID")
    parser.add_argument("--product-id",    type=int, help="DefectDojo product ID")
    args = parser.parse_args()
 
    if args.action == "test":
        ok = action_test_connection()
        sys.exit(0 if ok else 1)
 
    elif args.action == "setup":
        action_setup()
 
    elif args.action == "import":
        if not args.scan_type or not args.file:
            print("[ERROR] --scan-type and --file are required for import")
            sys.exit(1)
        eid = args.engagement_id
        if not eid:
            # Try to read from the env file created by setup
            env_file = "results/dojo_ids.env"
            if os.path.exists(env_file):
                with open(env_file) as f:
                    for line in f:
                        if line.startswith("DOJO_ENGAGEMENT_ID="):
                            eid = int(line.split("=")[1].strip())
        if not eid:
            print("[ERROR] --engagement-id required (or run --action setup first)")
            sys.exit(1)
        action_import(args.scan_type, args.file, eid)
 
    elif args.action == "findings":
        pid = args.product_id or int(os.getenv("DOJO_PRODUCT_ID", "0"))
        if not pid:
            print("[ERROR] --product-id required")
            sys.exit(1)
        action_list_findings(pid)
 
 
if __name__ == "__main__":
    main()