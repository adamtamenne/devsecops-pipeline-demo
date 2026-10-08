# DevSecOps CI/CD Pipeline Demo

A security-integrated CI/CD pipeline built with GitHub Actions, demonstrating how to embed automated security scanning at every phase of the software development lifecycle.

The repo contains an intentionally vulnerable Flask application and a five-stage pipeline that catches its vulnerabilities using open-source security tools. Each stage has a quality gate that blocks the build on critical or high-severity findings.

**This app is deliberately insecure. Do not deploy it.**

## Pipeline Architecture

```
Push / PR
    |
    v
[Stage 1: Secrets Scan]     Gitleaks
    |                        Scans full commit history for leaked
    |                        credentials, API keys, tokens.
    |                        WHY FIRST: a secret in a commit is
    |                        already exposed. Nothing else matters
    |                        until this passes.
    v
[Stage 2: SAST]              Semgrep (with custom rules)
    |                        Static analysis of source code for
[Stage 3: SCA]               Snyk
    |                        injection flaws, XSS, hardcoded
    |                        creds, debug flags, and known CVEs
    |                        in dependencies.
    |                        WHY HERE: catch code and dependency
    |                        issues before building the artifact.
    |                        Stages 2 and 3 run in parallel after
    |                        secrets scanning passes.
    v
[Stage 4: Container Scan]    Trivy
    |                        Scans the built Docker image for OS
    |                        package CVEs, misconfigurations, and
    |                        running as root.
    |                        WHY HERE: the base image and installed
    |                        packages can introduce vulnerabilities
    |                        even if the app code is clean.
    v
[Stage 5: DAST]              OWASP ZAP
    |                        Runs the containerized app and tests
    |                        it as a live target for XSS, SQLi,
    |                        missing security headers, and other
    |                        runtime vulnerabilities.
    |                        WHY LAST: DAST needs a running app.
    |                        It catches issues static analysis
    |                        misses (actual injection responses,
    |                        missing HTTP headers).
    v
[Result]  Pass --> merge allowed
          Fail --> PR blocked
```

All findings are uploaded as SARIF to GitHub's Security tab, so results are visible alongside the code in the repo's native security view.

## Intentional Vulnerabilities

The Flask app (`app/app.py`) contains the following OWASP Top 10 vulnerabilities, each mapped to the scanner that catches it:

| Vulnerability | OWASP | CWE | Caught by |
|---|---|---|---|
| SQL injection via string concatenation in `/search` | A03:2021 Injection | CWE-89 | Semgrep (SAST), ZAP (DAST) |
| Reflected XSS via `render_template_string` in `/profile` | A03:2021 Injection | CWE-79 | Semgrep (SAST), ZAP (DAST) |
| Hardcoded API key and database password | A07:2021 Auth Failures | CWE-798 | Gitleaks, Semgrep (custom rule) |
| Plaintext password storage and comparison | A07:2021 Auth Failures | CWE-256 | Semgrep (SAST) |
| No authorization check on `/notes/<user_id>` | A01:2021 Broken Access Control | CWE-862 | Manual review (not auto-detectable) |
| Flask debug mode enabled | A05:2021 Security Misconfiguration | CWE-489 | Semgrep (custom rule) |
| Dependencies with known CVEs | A06:2021 Vulnerable Components | various | Snyk (SCA) |
| Container running as root | A05:2021 Security Misconfiguration | various | Trivy |
| Missing security headers (CSP, HSTS, X-Content-Type-Options) | A05:2021 Security Misconfiguration | various | ZAP (DAST) |

## Custom Semgrep Rules

The repo includes three custom Semgrep rules in `security/semgrep-rules/` that go beyond the default rulesets:

- **hardcoded-api-key**: Flags variables matching the `sk_live_` pattern commonly used for production API keys.
- **sql-string-concat**: Detects SQL queries built with string concatenation followed by `.execute()`, a pattern Semgrep's `auto` config sometimes misses when the concatenation and execution are on separate lines.
- **flask-debug-enabled**: Catches `app.run(debug=True)`, which exposes the Werkzeug debugger and allows remote code execution.

## Quality Gates

Each pipeline stage is configured to fail the build (and block PR merges) when findings meet severity thresholds:

| Stage | Tool | Fail condition |
|---|---|---|
| Secrets | Gitleaks | Any secret detected |
| SAST | Semgrep | Any ERROR-severity finding |
| SCA | Snyk | Any HIGH or CRITICAL CVE |
| Container | Trivy | Any HIGH or CRITICAL CVE |
| DAST | ZAP | Rules configured as FAIL in `security/zap-config.yaml` |

Thresholds are intentionally strict for this demo. In a production pipeline you would tune these based on risk tolerance, potentially allowing WARN-level findings to pass while tracking them for remediation.

## Findings Triage

See [docs/findings-triage.md](docs/findings-triage.md) for a walkthrough of how to prioritize and remediate what this pipeline catches, using CVSS scoring, CWE classification, and business context.

## Running Locally

```bash
# Run the app
cd app
pip install -r requirements.txt
python app.py

# Run Semgrep locally
semgrep --config auto --config ./security/semgrep-rules/ app/

# Run Gitleaks locally
gitleaks detect --source . --verbose

# Build and scan the container
docker build -t devsecops-demo ./app
trivy image devsecops-demo
```

## Tools and Versions

- [Semgrep](https://semgrep.dev/) (SAST)
- [Snyk](https://snyk.io/) (SCA)
- [Gitleaks](https://gitleaks.io/) (Secrets)
- [Trivy](https://trivy.dev/) (Container scanning)
- [OWASP ZAP](https://www.zaproxy.org/) (DAST)

## License

MIT
