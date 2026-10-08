# Findings Triage Guide

How to prioritize and remediate the vulnerabilities this pipeline catches, ordered by severity and exploitability.

## Triage Framework

Each finding is assessed on three dimensions:

1. **Severity**: CVSS score and CWE classification
2. **Exploitability**: How easy is it to exploit in a real environment?
3. **Business impact**: What is the blast radius if exploited?

Remediation priority follows from these three factors combined, not CVSS alone. A critical CVSS score on an endpoint behind VPN and authentication is lower priority than a high-severity finding on a public, unauthenticated route.

## Findings by Priority

### P0: Fix immediately, block deployment

**Hardcoded API key (CWE-798)**
The `sk_live_` key in `app.py` is a production credential committed to source. Even if the repo is private, any developer with access can extract it, and it persists in git history after removal.
- Remediation: Rotate the key immediately. Load secrets from environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets). Add the key pattern to `.gitignore` and Gitleaks config.
- Caught by: Gitleaks (Stage 1), Semgrep custom rule (Stage 2)

**SQL injection in /search (CWE-89, CVSS 9.8)**
String concatenation in a SQL query on an unauthenticated endpoint. An attacker can extract the entire database, including plaintext passwords.
- Remediation: Replace string concatenation with parameterized queries: `db.execute("SELECT ... WHERE username LIKE ?", ("%" + query + "%",))`
- Caught by: Semgrep (Stage 2), ZAP (Stage 5)

### P1: Fix before next release

**Reflected XSS in /profile (CWE-79, CVSS 6.1)**
User-controlled input rendered directly into HTML via `render_template_string`. An attacker can craft a URL that executes JavaScript in another user's browser.
- Remediation: Use Jinja2 template files with autoescaping enabled (Flask's default when using `render_template` with `.html` files). Never concatenate user input into template strings.
- Caught by: Semgrep (Stage 2), ZAP (Stage 5)

**Flask debug mode enabled (CWE-489, CVSS 9.8)**
The Werkzeug debugger is accessible when `debug=True`. It provides an interactive Python console that allows arbitrary code execution on the server.
- Remediation: Set `debug=False` or use environment variables: `app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")`
- Caught by: Semgrep custom rule (Stage 2)

**Vulnerable dependencies (various CVEs)**
`requests==2.28.0` (CVE-2023-32681, Proxy-Authorization header leak), `cryptography==41.0.0` (CVE-2023-49083, NULL pointer dereference). These are known, patched vulnerabilities in production libraries.
- Remediation: Update to patched versions. Pin to the latest stable release and set up Dependabot or Snyk for ongoing monitoring.
- Caught by: Snyk (Stage 3)

### P2: Track and remediate in backlog

**Plaintext password storage (CWE-256)**
Passwords stored and compared as plaintext in SQLite. A database compromise exposes every credential.
- Remediation: Hash passwords with bcrypt or argon2. Compare hashes, never plaintext.
- Caught by: Semgrep (Stage 2)

**Missing security headers (CWE-693)**
No Content-Security-Policy, Strict-Transport-Security, or X-Content-Type-Options headers.
- Remediation: Add Flask-Talisman or set headers manually in a response middleware.
- Caught by: ZAP (Stage 5)

**Container running as root**
The Dockerfile does not specify a non-root user. A container escape gives the attacker root on the host.
- Remediation: Add `RUN useradd -r appuser` and `USER appuser` to the Dockerfile.
- Caught by: Trivy (Stage 4)

### Not auto-detectable

**Broken access control on /notes (CWE-862)**
Any user can access any other user's notes by changing the `user_id` in the URL. No scanner catches this because it requires business logic context: the scanner does not know that user A should not see user B's notes.
- Remediation: Validate that the authenticated user owns the requested resource. This is why manual code review and threat modeling remain essential even with a fully automated pipeline.

## Key Takeaway

Automated scanning catches a lot, but it does not catch everything. The broken access control vulnerability in this app is invisible to every scanner in the pipeline. A mature security program layers automated scanning with manual code review, threat modeling, and penetration testing.
