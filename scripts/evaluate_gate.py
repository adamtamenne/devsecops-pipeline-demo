#!/usr/bin/env python3
"""
Security Gate Evaluator

Reads scan results and evaluates them against the active policy phase
defined in security-policy.yml. Outputs a pass/warn/fail decision with
a summary suitable for PR comments and pipeline logs.

Usage:
    python evaluate_gate.py --scanner sast --results results/semgrep.json
    python evaluate_gate.py --scanner sca --results results/trivy-sca.json
    python evaluate_gate.py --scanner secrets --results results/gitleaks.json
    python evaluate_gate.py --scanner container --results results/trivy-image.json
    python evaluate_gate.py --scanner dast --results results/zap.json

Exit codes:
    0 = PASS (no findings above threshold, or phase is observe-only)
    1 = FAIL (findings exceed the active phase's block_on threshold)
    2 = WARN (findings present but below blocking threshold)
"""

import argparse
import json
import sys
import os
from pathlib import Path

import yaml


def load_policy(policy_path="security-policy.yml"):
    """Load the security policy configuration."""
    with open(policy_path, "r") as f:
        return yaml.safe_load(f)


def get_active_thresholds(policy, scanner):
    """Get the block/warn thresholds for the active phase and scanner."""
    active_phase = policy["active_phase"]
    phase_config = policy["phases"][active_phase]
    scanner_config = phase_config.get(scanner, {})

    return {
        "phase": active_phase,
        "description": phase_config["description"],
        "block_on": scanner_config.get("block_on", []),
        "warn_on": scanner_config.get("warn_on", []),
        "exit_code": scanner_config.get("exit_code", 0),
    }


def load_suppressions(policy, scanner):
    """Load active (non-expired) suppressions for this scanner."""
    from datetime import date

    today = date.today().isoformat()
    suppressions = policy.get("suppressions", [])
    active = []
    for s in suppressions:
        if s.get("scanner") == scanner and s.get("expires", "9999-12-31") > today:
            active.append(s["id"])
    return active


def parse_results(scanner, results_path):
    """
    Parse scan results into a normalized list of findings.
    Each finding has: id, severity, title/description.

    Extend this function to support your specific tool output formats.
    """
    with open(results_path, "r") as f:
        raw = json.load(f)

    findings = []

    if scanner == "sast":
        # Semgrep JSON output format
        for result in raw.get("results", []):
            severity = result.get("extra", {}).get("severity", "INFO").lower()
            findings.append({
                "id": result.get("check_id", "unknown"),
                "severity": severity,
                "title": result.get("extra", {}).get("message", ""),
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
            })

    elif scanner == "sca":
        # Trivy JSON output format (fs/repo mode)
        for target in raw.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").lower()
                findings.append({
                    "id": vuln.get("VulnerabilityID", "unknown"),
                    "severity": severity,
                    "title": vuln.get("Title", ""),
                    "package": vuln.get("PkgName", ""),
                    "fix_available": vuln.get("FixedVersion", "") != "",
                })

    elif scanner == "secrets":
        # Gitleaks JSON output format
        if isinstance(raw, list):
            for finding in raw:
                findings.append({
                    "id": finding.get("RuleID", "unknown"),
                    "severity": "critical",
                    "title": finding.get("Description", "Secret detected"),
                    "file": finding.get("File", ""),
                    "line": finding.get("StartLine", 0),
                })

    elif scanner == "container":
        # Trivy JSON output format (image mode)
        for target in raw.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").lower()
                findings.append({
                    "id": vuln.get("VulnerabilityID", "unknown"),
                    "severity": severity,
                    "title": vuln.get("Title", ""),
                    "package": vuln.get("PkgName", ""),
                })

    elif scanner == "dast":
        # ZAP JSON output format
        for site in raw.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskcode", "0")
                severity_map = {"3": "high", "2": "medium", "1": "low", "0": "informational"}
                severity = severity_map.get(risk, "informational")
                findings.append({
                    "id": alert.get("pluginid", "unknown"),
                    "severity": severity,
                    "title": alert.get("name", ""),
                    "count": int(alert.get("count", 1)),
                })

    return findings


def evaluate(findings, thresholds, suppressions):
    """
    Evaluate findings against policy thresholds.
    Returns (decision, summary) where decision is PASS, WARN, or FAIL.
    """
    # Filter out suppressed findings
    active_findings = [f for f in findings if f["id"] not in suppressions]
    suppressed_count = len(findings) - len(active_findings)

    # Count by severity
    severity_counts = {}
    for f in active_findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Check for blocking findings
    block_severities = thresholds["block_on"]
    warn_severities = thresholds["warn_on"]

    blocking_count = 0
    warning_count = 0

    for sev, count in severity_counts.items():
        if "all" in block_severities or sev in block_severities:
            blocking_count += count
        elif "all" in warn_severities or sev in warn_severities:
            warning_count += count

    # Build summary
    summary = {
        "total_findings": len(active_findings),
        "suppressed": suppressed_count,
        "by_severity": severity_counts,
        "blocking": blocking_count,
        "warnings": warning_count,
    }

    if blocking_count > 0 and thresholds["exit_code"] != 0:
        return "FAIL", summary
    elif warning_count > 0 or blocking_count > 0:
        return "WARN", summary
    else:
        return "PASS", summary


def format_output(scanner, decision, summary, thresholds):
    """Format the gate result for pipeline output."""
    phase = thresholds["phase"].replace("_", " ").title()
    desc = thresholds["description"]

    lines = [
        f"{'=' * 60}",
        f"  SECURITY GATE: {scanner.upper()}",
        f"  Policy Phase: {phase} ({desc})",
        f"  Decision: {decision}",