/**
 * mock-app/server.js
 *
 * Intentionally vulnerable web application for Kubernetes Ingress Security testing.
 *
 * VULNERABILITY MAP:
 * ------------------
 * GET  /search?q=        → SQL Injection + XSS (reflected input, fake DB query)
 * GET  /files?name=      → Path Traversal (reads files from a sandboxed directory)
 * GET  /health           → Health check (used by k8s liveness/readiness probes)
 * GET  /metrics          → Exposes request count (used for performance benchmarking)
 * POST /login            → SQL Injection via POST body
 * GET  /                 → Serves the frontend UI
 *
 * WHY THESE ENDPOINTS:
 * --------------------
 * - /search : Most common XSS + SQLi attack surface (search boxes). Reflects
 *             the `q` param directly into the HTML response without sanitisation.
 * - /files  : Classic path traversal target. Naively joins user input onto a base
 *             path, allowing ../../etc/passwd style traversal attempts.
 * - /login  : POST-based SQLi, tests WAF on request bodies not just query strings.
 * - /health + /metrics : Required for Kubernetes probes and your benchmarking scripts.
 */

const express = require('express');
const path    = require('path');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Simple in-memory metrics (for /metrics endpoint) ─────────────────────────
let requestCount = 0;
let attackAttempts = { sqli: 0, xss: 0, traversal: 0 };

app.use((req, res, next) => {
  requestCount++;
  next();
});

// ── Health check ─────────────────────────────────────────────────────────────
// Required for Kubernetes liveness and readiness probes.
// Without this, k8s will think the pod is unhealthy and restart it during tests.
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// ── Metrics ──────────────────────────────────────────────────────────────────
// Exposes simple counters so you can verify during benchmarking how many
// requests actually reached the backend (vs were blocked by WAF/rate limiting).
app.get('/metrics', (req, res) => {
  res.json({
    totalRequests: requestCount,
    attackAttempts,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
  });
});

// ── VULNERABILITY 1: Reflected XSS + SQL Injection (GET /search) ─────────────
//
// WHY VULNERABLE:
//   The `q` parameter is interpolated directly into:
//     (a) a fake SQL query string shown in the response  → SQL Injection demo
//     (b) the HTML body without escaping               → Reflected XSS demo
//
// WHAT THIS LETS YOU TEST:
//   SQLi payload : ?q=' OR '1'='1
//     → The fake query echoes back showing the injection succeeded.
//       On Solution 1 (default) this reaches the app.
//       On Solution 2 (hardened) ModSecurity blocks it with a 403.
//
//   XSS payload  : ?q=<script>alert(document.cookie)</script>
//     → On Solution 1 the script tag is reflected raw into the HTML.
//       On Solution 2 ModSecurity blocks it.
//
app.get('/search', (req, res) => {
  const query = req.query.q || '';

  // Naive detection just for the metrics counter — not a real defence
  if (query.includes("'") || query.toLowerCase().includes('or ')) {
    attackAttempts.sqli++;
  }
  if (query.includes('<') || query.toLowerCase().includes('script')) {
    attackAttempts.xss++;
  }

  // Simulate a DB query string (no real DB needed)
  const fakeSQL = `SELECT * FROM products WHERE name = '${query}'`;

  // INTENTIONALLY unescaped — reflects raw input into HTML
  const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Search Results</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="container">
    <h2>Search Results for: ${query}</h2>
    <div class="sql-box">
      <p class="label">Executed query:</p>
      <code>${fakeSQL}</code>
    </div>
    <ul class="results">
      <li>Product Alpha — $10.00</li>
      <li>Product Beta — $24.99</li>
      <li>Product Gamma — $5.49</li>
    </ul>
    <a href="/">← Back</a>
  </div>
</body>
</html>`;

  res.send(html);
});

// ── VULNERABILITY 2: Path Traversal (GET /files) ──────────────────────────────
//
// WHY VULNERABLE:
//   The `name` parameter is naively joined onto a base directory with no
//   sanitisation. An attacker can supply ../../etc/passwd to walk up the tree.
//
// WHAT THIS LETS YOU TEST:
//   Payload: ?name=../../etc/passwd
//     → On Solution 1 (default): the server attempts to read the path and
//       returns either file contents or a Node.js error that leaks the real path.
//     → On Solution 2 (hardened): ModSecurity blocks the request (the ../ 
//       sequence matches OWASP CRS rule 930110).
//
// NOTE: The container runs as UID 1001 with readOnlyRootFilesystem, so even
// on Solution 1 the actual damage is limited — but the traversal attempt
// still reaches the app and produces a revealing error, which is the point.
//
const FILES_BASE = path.join(__dirname, 'public', 'files');
// Pre-create a few legitimate files for normal use
fs.mkdirSync(FILES_BASE, { recursive: true });
fs.writeFileSync(path.join(FILES_BASE, 'readme.txt'),  'Welcome to the mock app file store.\n');
fs.writeFileSync(path.join(FILES_BASE, 'products.txt'), 'Alpha\nBeta\nGamma\n');

app.get('/files', (req, res) => {
  const fileName = req.query.name || 'readme.txt';

  // Track traversal attempts (naive heuristic)
  if (fileName.includes('..') || fileName.startsWith('/')) {
    attackAttempts.traversal++;
  }

  // INTENTIONALLY vulnerable join — no path normalisation or containment check
  const filePath = path.join(FILES_BASE, fileName);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      // Error message intentionally leaks the resolved path — realistic mistake
      return res.status(404).send(`
        <div class="error">
          Could not read file: <code>${filePath}</code><br>
          Error: ${err.message}
        </div>`);
    }
    res.type('text/plain').send(data);
  });
});

// ── VULNERABILITY 3: SQL Injection via POST /login ────────────────────────────
//
// WHY VULNERABLE:
//   Username is interpolated into a fake SQL query without parameterisation.
//   Classic auth-bypass payload: username = admin' --
//
// WHAT THIS LETS YOU TEST:
//   POST body SQLi — some WAFs only inspect query strings, not request bodies.
//   ModSecurity with OWASP CRS inspects both, so this tests that rule coverage
//   is comprehensive across HTTP methods and input locations.
//
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  if (username.includes("'") || username.toLowerCase().includes('--')) {
    attackAttempts.sqli++;
  }

  // Fake query — no real DB
  const fakeSQL = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

  // Simulate auth-bypass: if the injected query "succeeds"
  const bypassDetected = username.includes("'") || username.includes('--');

  res.json({
    query: fakeSQL,
    authenticated: bypassDetected,   // true when injection works — makes the demo clear
    message: bypassDetected
      ? '⚠️  Auth bypass successful — injection detected in query'
      : 'Login failed: invalid credentials',
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Mock vulnerable app running on port ${PORT}`);
  console.log('Endpoints: /, /search, /files, /login, /health, /metrics');
});
