#!/usr/bin/env bash
# attacks/run-attacks.sh
#
# Manual attack scripts for both deployments.
# Usage: BASE_URL=http://localhost:8080 bash run-attacks.sh
#
# Run against Solution 1: BASE_URL=http://<default-service>
# Run against Solution 2: BASE_URL=https://<hardened-service> (add -k for self-signed cert)
#
# Expected results:
#   Solution 1 (default) : all attacks reach the backend → HTTP 200 with payload reflected
#   Solution 2 (hardened): ModSecurity/rate-limiter blocks → HTTP 403 or 429

BASE_URL="${BASE_URL:-http://localhost:3000}"
TLS_FLAG=""   # set to "-k" if using self-signed cert on hardened deployment

echo "============================================================"
echo " Target: $BASE_URL"
echo "============================================================"

# ── Helper ────────────────────────────────────────────────────────────────────
run() {
  local label="$1"; shift
  echo ""
  echo "── $label ──"
  echo "CMD: curl $*"
  echo "RESPONSE:"
  curl -s -o /dev/null -w "HTTP %{http_code} | time_total: %{time_total}s\n" \
    $TLS_FLAG "$@"
}

# ── 1. SQL INJECTION (GET) ────────────────────────────────────────────────────
# Payload: classic tautology that would bypass a WHERE clause
# Expected on Solution 1: HTTP 200 — query is reflected in the page
# Expected on Solution 2: HTTP 403 — ModSecurity OWASP CRS rule 942100 fires
run "SQLi GET — tautology" \
  "$BASE_URL/search?q=%27+OR+%271%27%3D%271"

# Union-based payload
run "SQLi GET — UNION SELECT" \
  "$BASE_URL/search?q=%27+UNION+SELECT+username%2Cpassword+FROM+users--"

# ── 2. SQL INJECTION (POST) ───────────────────────────────────────────────────
# Tests that WAF inspects request bodies, not just query strings
# Expected on Solution 1: HTTP 200, authenticated: true in JSON response
# Expected on Solution 2: HTTP 403
run "SQLi POST — auth bypass" \
  -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' --","password":"anything"}'

# ── 3. CROSS-SITE SCRIPTING (XSS) ────────────────────────────────────────────
# Payload is reflected raw into the HTML page on Solution 1
# ModSecurity OWASP CRS rule 941100 should block it on Solution 2
run "XSS — script tag" \
  "$BASE_URL/search?q=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E"

run "XSS — img onerror" \
  "$BASE_URL/search?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"

# ── 4. PATH TRAVERSAL ─────────────────────────────────────────────────────────
# ModSecurity OWASP CRS rule 930110 detects ../ sequences
# On Solution 1: server attempts to read the file, leaks path in error message
# On Solution 2: HTTP 403 before request reaches the app
run "Path Traversal — /etc/passwd" \
  "$BASE_URL/files?name=../../etc/passwd"

run "Path Traversal — /etc/hostname" \
  "$BASE_URL/files?name=../../etc/hostname"

run "Path Traversal — server source" \
  "$BASE_URL/files?name=../server.js"

# ── 5. DDOS SIMULATION ───────────────────────────────────────────────────────
# Requires: wrk (brew install wrk / apt install wrk)
# Sends 500 concurrent connections for 30 seconds
# On Solution 1: server degrades or times out, latency climbs
# On Solution 2: rate limiter returns 429 after threshold, server stays stable
echo ""
echo "── DDoS simulation (wrk) ──"
if command -v wrk &>/dev/null; then
  wrk -t4 -c500 -d30s --latency "$BASE_URL/"
else
  echo "wrk not installed. Falling back to ab (Apache Bench):"
  if command -v ab &>/dev/null; then
    ab -n 10000 -c 200 "$BASE_URL/"
  else
    echo "Neither wrk nor ab found. Install one of them to run the DDoS test."
    echo "  macOS : brew install wrk"
    echo "  Ubuntu: sudo apt install wrk apache2-utils"
  fi
fi

# ── 6. CHECK METRICS (how many requests actually reached the backend) ──────────
echo ""
echo "── Backend metrics (requests that bypassed WAF/rate-limit) ──"
curl -s $TLS_FLAG "$BASE_URL/metrics" | python3 -m json.tool 2>/dev/null || \
  curl -s $TLS_FLAG "$BASE_URL/metrics"

echo ""
echo "============================================================"
echo " Done. Compare HTTP status codes between both deployments."
echo "============================================================"
