# DevSecOps CI/CD Pipeline Demo

A complete, security-integrated CI/CD pipeline built on GitHub Actions, designed to show how application security scanning, policy enforcement, and supply chain integrity work together in a real development workflow.

The repo contains an intentionally vulnerable Flask application with OWASP Top 10 vulnerabilities planted across its endpoints. A five-stage pipeline detects those vulnerabilities using open-source security tools, enforces configurable policy gates, generates a Software Bill of Materials, and signs the container image for supply chain integrity.

**This app is deliberately insecure. Do not deploy it.**

## Why This Exists

In a consulting engagement, the question isn't "can you install a scanner?" It's "can you operationalize security scanning so development teams adopt it, trust it, and act on it?" This repo demonstrates that full lifecycle:

1. **Build** a vulnerable application with realistic flaws
2. **Scan** it with five different tools, each catching what the others miss
3. **Enforce** findings through configurable policy gates that start permissive and tighten over time
4. **Document** the supply chain with SBOMs and signed artifacts
5. **Validate** findings manually with Burp Suite (see [manual-validation walkthrough](docs/manual-validation.md))

---

## Pipeline Architecture

The pipeline runs five stages in order. Each stage has a specific reason for its position, and each tool is chosen for what it catches that the others can't.

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
[Stage 4: Container Scan]    Trivy + Syft + Cosign
    |                        Scans the built Docker image for OS
    |                        package CVEs, misconfigurations, and
    |                        running as root. Generates an SBOM
    |                        (CycloneDX) and signs the image with
    |                        Cosign for supply chain integrity.
    |                        WHY HERE: the base image and installed
    |                        packages can introduce vulnerabilities
    |                        even if the app code is clean. The SBOM
    |                        and signature provide SLSA Level 2
    |                        provenance: proof of what's in the
    |                        artifact and that it hasn't been
    |                        tampered with.
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

The stage ordering isn't arbitrary. Secrets run first because a leaked credential is already exposed regardless of code quality. SAST and SCA run in parallel because they analyze different things (your code vs your dependencies) and neither depends on the other. Container scanning runs after the image is built because base image vulnerabilities are invisible until then. DAST runs last because it needs a running application to test against.

---

## Intentional Vulnerabilities

The Flask app (`app/app.py`) contains deliberate OWASP Top 10 vulnerabilities. Each one is mapped to the scanner that catches it and the OWASP/CWE classification. This is the same mapping you'd produce in a client assessment report.

| Vulnerability | OWASP | CWE | Caught by |
|---|---|---|---|
| SQL injection via string concatenation in `/search` | A03:2021 Injection | CWE-89 | Semgrep (SAST), ZAP (DAST) |
| Reflected XSS via `render_template_string` in `/profile` | A03:2021 Injection | CWE-79 | Semgrep (SAST), ZAP (DAST) |
| Hardcoded API key and database password | A07:2021 Auth Failures | CWE-798 | Gitleaks, Semgrep (custom rule) |
| Plaintext password storage and comparison | A07:2021 Auth Failures | CWE-256 | Semgrep (SAST) |
| No rate limiting on `/login` | A07:2021 Auth Failures | CWE-307 | Manual testing (Burp Suite) |
| No authorization check on `/notes/<user_id>` | A01:2021 Broken Access Control | CWE-862 | Manual review (BOLA) |
| Insecure deserialization via `pickle.loads` in `/load` | A08:2021 Integrity Failures | CWE-502 | Semgrep (SAST), Manual testing |
| Server-Side Request Forgery in `/fetch` | A10:2021 SSRF | CWE-918 | Manual testing (Burp Suite) |
| Flask debug mode enabled | A05:2021 Security Misconfiguration | CWE-489 | Semgrep (custom rule) |
| Server version leakage in response headers | A05:2021 Security Misconfiguration | CWE-200 | ZAP (DAST), Manual testing |
| Missing security headers (CSP, HSTS, X-Content-Type-Options) | A05:2021 Security Misconfiguration | CWE-693 | ZAP (DAST) |
| Dependencies with known CVEs | A06:2021 Vulnerable Components | various | Snyk (SCA) |
| Container running as root | A05:2021 Security Misconfiguration | various | Trivy |
| No security logging on authentication events | A09:2021 Logging Failures | CWE-778 | Manual review |

Notice that some vulnerabilities are caught by multiple scanners (SQLi appears in both SAST and DAST), some are only caught by one tool type (SSRF requires manual testing), and some can't be caught by automation at all (broken access control requires understanding the business logic). That layered coverage is why a single scanner is never enough.

For detailed manual exploitation and remediation of each finding with Burp Suite screenshots, see [docs/manual-validation.md](docs/manual-validation.md).

---

## Custom Semgrep Rules

Default SAST rulesets miss patterns that are specific to your codebase or technology stack. Writing custom rules is how you close those gaps. This repo includes three custom Semgrep rules in `security/semgrep-rules/` that demonstrate this:

- **hardcoded-api-key**: Flags variables matching the `sk_live_` pattern commonly used for production API keys. Default rulesets catch generic secrets but miss vendor-specific patterns.
- **sql-string-concat**: Detects SQL queries built with string concatenation followed by `.execute()`. Semgrep's `auto` config sometimes misses this when the concatenation and execution are on separate lines.
- **flask-debug-enabled**: Catches `app.run(debug=True)`, which exposes the Werkzeug interactive debugger and allows remote code execution. This is a critical misconfiguration that's easy to leave in production code.

In a consulting engagement, you'd write custom rules tailored to the client's tech stack and common vulnerability patterns. These three demonstrate the approach.

---

## Security Policy Gates

### The Problem

Turning all security gates to blocking on day one breaks developer trust. A team that gets blocked by 200 findings on their first PR learns to work around the tooling, not with it. Once that habit forms, it's hard to reverse.

### The Solution: Phased Enforcement

This pipeline uses configurable policy gates controlled by a single file (`security-policy.yml`). One line change switches the enforcement level. No pipeline rewrites needed.

| Phase | Behavior | When to use |
|-------|----------|-------------|
| **Phase 1: Observe** | All scanners report findings but nothing blocks the pipeline | First 1-2 weeks. Establish a baseline, identify noisy rules, tune false positives |
| **Phase 2: Gate Critical** | Critical and high severity block; medium is a warning | Weeks 3-6. Catch RCE, injection, leaked secrets without blocking on unvalidated noise |
| **Phase 3: Enforce** | Medium and above block; low is informational | Week 7+. Only after tooling is tuned and teams have adopted remediation workflows |

This phased model is designed for consulting engagements. Every new client starts on Phase 1. You observe, tune, remove the noise. Then you tighten. The client's security team controls the policy file while developers own the pipeline. Separation of concerns.

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

Expired suppressions automatically re-activate the finding. This prevents the common problem of suppressions becoming permanent ignore rules that nobody revisits.

---

## Supply Chain Security (SLSA Level 2)

Scanning for vulnerabilities is only half the problem. The other half is: can you trust that what you're deploying is actually what went through your pipeline?

The container scan stage includes two supply chain security steps that address this:

### SBOM Generation

After building the Docker image, the pipeline generates a Software Bill of Materials (CycloneDX format) listing every component, version, and package URL in the image. The SBOM is stored as a build artifact alongside the image.

The value is incident response speed. When a zero-day drops (like Log4Shell), you search the SBOMs across all your builds instead of manually checking every codebase. Minutes instead of days.

```bash
# Generate locally
cyclonedx-py requirements -i requirements.txt --output-format JSON -o sbom.json
```

### Container Signing

The built image is signed with Sigstore's Cosign using keyless signing tied to the GitHub Actions identity. The signature is recorded in Rekor's public transparency log. Before deploying, you verify the signature to confirm the image hasn't been tampered with since it left the pipeline.

Together, these provide SLSA Level 2 provenance: a signed, verifiable record of what was built, when, from what source, and on what build system. This is the chain of custody that answers "can I trust that what I'm deploying is what went through my security pipeline?"

---

## Findings Triage

See [docs/findings-triage.md](docs/findings-triage.md) for a walkthrough of how to prioritize and remediate what this pipeline catches, using CVSS scoring, CWE classification, and business context.

## Manual Validation

See [docs/manual-validation.md](docs/manual-validation.md) for hands-on exploitation and remediation of each vulnerability using Burp Suite, with screenshots showing the exact requests, responses, and proof of exploitability.

---

## Running Locally

```bash
# Run the app
cd app
pip install -r requirements.txt
flask run --port 5001

# Run Semgrep locally
semgrep --config auto --config ./security/semgrep-rules/ app/

# Run Gitleaks locally
gitleaks detect --source . --verbose

# Build and scan the container
docker build -t devsecops-demo ./app
trivy image devsecops-demo

# Generate an SBOM
cyclonedx-py requirements -i app/requirements.txt --output-format JSON -o sbom.json
```

## Tools

- [Semgrep](https://semgrep.dev/) (SAST)
- [Snyk](https://snyk.io/) (SCA)
- [Gitleaks](https://gitleaks.io/) (Secrets)
- [Trivy](https://trivy.dev/) (Container scanning)
- [OWASP ZAP](https://www.zaproxy.org/) (DAST)
- [Cosign / Sigstore](https://www.sigstore.dev/) (Container signing)
- [CycloneDX](https://cyclonedx.org/) (SBOM generation)
- [Burp Suite](https://portswigger.net/burp) (Manual validation)

## License

MIT
