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

## Security Policy Gates

### Why Phased Enforcement?

Turning all security gates to blocking on day one is the fastest way to kill developer trust in your security tooling. Teams learn to work around tools they see as obstacles, and once that habit forms, it's hard to reverse.

This pipeline uses a phased rollout model, controlled by a single configuration file (`security-policy.yml`), that lets you start permissive and tighten as the tooling earns trust:

| Phase | Behavior | When to use |
|-------|----------|-------------|
| **Phase 1: Observe** | All scanners report findings but nothing blocks the pipeline | First 1-2 weeks. Establish a baseline, identify noisy rules, tune false positives |
| **Phase 2: Gate Critical** | Critical and high severity block; medium is a warning | Weeks 3-6. Catch RCE, injection, leaked secrets without blocking on unvalidated noise |
| **Phase 3: Enforce** | Medium and above block; low is informational | Week 7+. Only after tooling is tuned and teams have adopted remediation workflows |

### How It Works

1. `security-policy.yml` defines thresholds per scanner per phase
2. Each pipeline stage runs its scanner with `continue-on-error: true`
3. `scripts/evaluate_gate.py` reads the scan results, applies the active phase's thresholds, filters out suppressions, and exits with the appropriate code
4. Changing enforcement is a one-line config change (`active_phase`), not a pipeline rewrite

### Switching Phases

```yaml
# security-policy.yml
active_phase: "phase_2"  # Change this to roll forward or back
```

No workflow changes needed. The security team controls the policy file while developers own the pipeline. Separation of concerns.

### Suppressions

Suppressions require a justification, expiration date, and approver. Every suppression is a documented risk acceptance decision, not a way to silence findings permanently.

```yaml
suppressions:
  - id: "CVE-2024-0001"
    scanner: "sca"
    reason: "No patch available; mitigated by WAF rule."
    expires: "2025-03-01"
    approved_by: "security-team"
```

Expired suppressions automatically re-activate the finding.