#!/usr/bin/env python3
"""
Quantum-Readiness Auditor for a mock cloud environment.

Scans an inventory of TLS/SSL certificates, SSH keys, and TLS endpoint
configurations, classifies each cryptographic asset against NIST's
post-quantum guidance, and produces a migration report.

Usage:
    python quantum_audit.py --generate-mock inventory.json
    python quantum_audit.py --input inventory.json --output report.md
    python quantum_audit.py --input inventory.json --output report.json --format json
"""

from __future__ import annotations

import argparse
import json
import random
import re
from dataclasses import dataclass, field, asdict
from datetime import date, timedelta
from enum import Enum


# ---------------------------------------------------------------------------
# Classification model
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    SAFE = "SAFE"


# Algorithms broken outright by Shor's algorithm on a sufficiently large
# quantum computer. Anything matching these (regardless of key size) is
# "Quantum-Vulnerable".
SHOR_VULNERABLE_PATTERNS = [
    r"^RSA",
    r"^DSA",
    r"^ECDSA",
    r"^ECDH",
    r"^EC[- ]",
    r"^ED25519",
    r"^ED448",
    r"^X25519",
    r"^X448",
]

# Post-quantum / NIST-selected algorithms.
PQC_PATTERNS = [
    r"^ML-KEM", r"^KYBER",
    r"^ML-DSA", r"^DILITHIUM",
    r"^FALCON",
    r"^SLH-DSA", r"^SPHINCS",
]

# Symmetric ciphers weakened (not broken) by Grover's algorithm.
GROVER_WEAKENED_PATTERNS = [
    r"^AES-128", r"^AES_128", r"^3DES", r"^CHACHA20-128",
]

PQC_SIGNATURE_RECOMMENDATION = "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)"
PQC_KEM_RECOMMENDATION = "ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange"


def _matches_any(value: str, patterns: list[str]) -> bool:
    return any(re.match(p, value, re.IGNORECASE) for p in patterns)


@dataclass
class Finding:
    asset_type: str          # "Certificate", "SSH Key", "TLS Config"
    resource_id: str
    resource_name: str
    detail: str               # e.g. "RSA-2048", "ECDHE-RSA-AES128-GCM-SHA256"
    status: str                # Quantum-Vulnerable / Quantum-Weakened / Quantum-Safe
    severity: Severity
    reason: str
    recommendation: str
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Classification rules
# ---------------------------------------------------------------------------

def classify_asymmetric_algorithm(algorithm: str, key_size: int | None = None) -> Finding:
    """Classify a public-key algorithm used by a certificate or SSH key."""
    algo = algorithm.strip().upper()

    if _matches_any(algo, PQC_PATTERNS):
        return _result(
            status="Quantum-Safe",
            severity=Severity.SAFE,
            reason=f"{algorithm} is a NIST post-quantum algorithm.",
            recommendation="No action needed.",
        )

    if _matches_any(algo, SHOR_VULNERABLE_PATTERNS):
        if algo.startswith("RSA"):
            severity = Severity.CRITICAL if (key_size or 0) < 2048 else Severity.HIGH
            recommendation = (
                f"Replace RSA{'' if not key_size else '-' + str(key_size)} with "
                f"{PQC_SIGNATURE_RECOMMENDATION} (or a hybrid RSA+PQC certificate "
                f"during transition)."
            )
        else:
            severity = Severity.HIGH
            recommendation = (
                f"Replace {algorithm} with {PQC_SIGNATURE_RECOMMENDATION} for "
                f"signing, and {PQC_KEM_RECOMMENDATION} for key exchange."
            )
        return _result(
            status="Quantum-Vulnerable",
            severity=severity,
            reason=(
                f"{algorithm} relies on integer factorization or discrete-log "
                f"hardness, both broken by Shor's algorithm on a CRQC."
            ),
            recommendation=recommendation,
        )

    if _matches_any(algo, GROVER_WEAKENED_PATTERNS):
        return _result(
            status="Quantum-Weakened",
            severity=Severity.MEDIUM,
            reason=f"{algorithm} keyspace is halved by Grover's algorithm.",
            recommendation="Upgrade to AES-256 or an equivalent 256-bit symmetric cipher.",
        )

    return _result(
        status="Quantum-Safe",
        severity=Severity.SAFE,
        reason=f"{algorithm} has no known efficient quantum attack.",
        recommendation="No action needed.",
    )


def classify_cipher_suite(suite: str) -> Finding:
    """Classify a TLS cipher suite string, e.g. 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'."""
    s = suite.strip().upper()

    issues = []
    if "RSA" in s and "ECDHE" not in s and "DHE" not in s:
        issues.append(("RSA key exchange", Severity.CRITICAL, PQC_KEM_RECOMMENDATION))
    if "ECDHE" in s or "ECDH" in s:
        issues.append(("ECDHE key exchange", Severity.HIGH, PQC_KEM_RECOMMENDATION))
    if re.search(r"_RSA(_|$)", s) or "WITH_RSA" in s:
        issues.append(("RSA authentication", Severity.HIGH, PQC_SIGNATURE_RECOMMENDATION))
    if "ECDSA" in s:
        issues.append(("ECDSA authentication", Severity.HIGH, PQC_SIGNATURE_RECOMMENDATION))
    if "AES_128" in s or "AES128" in s:
        issues.append(("AES-128 bulk cipher", Severity.MEDIUM, "AES-256"))
    if re.search(r"_3DES|DES_CBC|RC4", s):
        issues.append(("legacy/broken bulk cipher", Severity.CRITICAL, "AES-256-GCM or ChaCha20-Poly1305"))

    if not issues:
        return _result(
            status="Quantum-Safe",
            severity=Severity.SAFE,
            reason=f"{suite} uses no algorithms with known quantum breaks.",
            recommendation="No action needed.",
        )

    # Worst severity wins; combine reasons/recommendations.
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.SAFE]
    worst = min(issues, key=lambda i: severity_order.index(i[1]))[1]
    reason = "; ".join(f"{name} (quantum-{'broken' if sev != Severity.MEDIUM else 'weakened'})"
                        for name, sev, _ in issues)
    recs = sorted({rec for _, _, rec in issues})
    status = "Quantum-Vulnerable" if worst in (Severity.CRITICAL, Severity.HIGH) else "Quantum-Weakened"

    return _result(
        status=status,
        severity=worst,
        reason=reason,
        recommendation="Migrate to: " + "; ".join(recs) + ". Prefer TLS 1.3 cipher suites.",
    )


def classify_key_exchange_group(group: str) -> dict:
    """Classify a TLS supported_group / negotiated key-exchange group, e.g.
    'X25519', 'secp256r1', or a hybrid PQC group like 'X25519MLKEM768'."""
    g = group.strip().upper()

    if _matches_any(g, PQC_PATTERNS) or re.search(r"MLKEM|KYBER", g):
        if re.search(r"X25519|P256|P384|SECP|ECDH", g):
            return _result(
                status="Quantum-Safe",
                severity=Severity.SAFE,
                reason=(
                    f"{group} is a hybrid key exchange combining a classical ECDH "
                    "share with an ML-KEM/Kyber share — recovering the shared "
                    "secret requires breaking both."
                ),
                recommendation="No action needed.",
            )
        return _result(
            status="Quantum-Safe",
            severity=Severity.SAFE,
            reason=f"{group} is a NIST post-quantum KEM.",
            recommendation="No action needed.",
        )

    if re.search(r"X25519|X448|SECP|P-?(256|384|521)|ECDH", g):
        return _result(
            status="Quantum-Vulnerable",
            severity=Severity.HIGH,
            reason=(
                f"{group} is a classical (EC)DHE group; its discrete-log "
                "hardness is broken by Shor's algorithm on a CRQC."
            ),
            recommendation=f"Negotiate a hybrid group, e.g. {PQC_KEM_RECOMMENDATION}.",
        )

    if re.search(r"^FFDHE|^DH", g):
        return _result(
            status="Quantum-Vulnerable",
            severity=Severity.HIGH,
            reason=f"{group} is finite-field Diffie-Hellman, broken by Shor's algorithm on a CRQC.",
            recommendation=f"Negotiate a hybrid group, e.g. {PQC_KEM_RECOMMENDATION}.",
        )

    return _result(
        status="Quantum-Safe",
        severity=Severity.SAFE,
        reason=f"{group} has no known efficient quantum attack.",
        recommendation="No action needed.",
    )


def _result(status: str, severity: Severity, reason: str, recommendation: str) -> dict:
    """Small helper bundling the parts of a Finding that classifiers compute."""
    return {
        "status": status,
        "severity": severity,
        "reason": reason,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Mock environment generator
# ---------------------------------------------------------------------------

def generate_mock_environment(seed: int | None = 42) -> dict:
    rng = random.Random(seed)
    today = date.today()

    certificates = [
        {
            "resource_id": "arn:aws:acm:us-east-1:111122223333:certificate/aaa-111",
            "resource_name": "api.shopcart.example.com",
            "algorithm": "RSA",
            "key_size": 2048,
            "issuer": "Amazon",
            "expires": (today + timedelta(days=180)).isoformat(),
        },
        {
            "resource_id": "arn:aws:acm:us-east-1:111122223333:certificate/bbb-222",
            "resource_name": "legacy-vpn.shopcart.example.com",
            "algorithm": "RSA",
            "key_size": 1024,
            "issuer": "InternalCA",
            "expires": (today + timedelta(days=30)).isoformat(),
        },
        {
            "resource_id": "arn:aws:acm:eu-west-1:111122223333:certificate/ccc-333",
            "resource_name": "edge.shopcart.example.com",
            "algorithm": "ECDSA",
            "key_size": 256,
            "issuer": "Amazon",
            "expires": (today + timedelta(days=300)).isoformat(),
        },
        {
            "resource_id": "kv:contoso-vault:cert/internal-svc",
            "resource_name": "internal-svc.contoso.local",
            "algorithm": "RSA",
            "key_size": 4096,
            "issuer": "ContosoCA",
            "expires": (today + timedelta(days=400)).isoformat(),
        },
        {
            "resource_id": "kv:contoso-vault:cert/pqc-pilot",
            "resource_name": "pilot.contoso.local",
            "algorithm": "ML-DSA-65",
            "key_size": None,
            "issuer": "ContosoCA-PQC",
            "expires": (today + timedelta(days=365)).isoformat(),
        },
    ]

    ssh_keys = [
        {
            "resource_id": "ec2-keypair/prod-bastion",
            "resource_name": "prod-bastion-key",
            "key_type": "RSA",
            "key_size": 2048,
            "attached_to": ["i-0a1b2c3d4e5f60001 (bastion-host)"],
        },
        {
            "resource_id": "ec2-keypair/build-agent",
            "resource_name": "build-agent-key",
            "key_type": "ED25519",
            "key_size": 256,
            "attached_to": ["i-0a1b2c3d4e5f60002 (ci-runner-1)"],
        },
        {
            "resource_id": "ec2-keypair/legacy-db",
            "resource_name": "legacy-db-key",
            "key_type": "DSA",
            "key_size": 1024,
            "attached_to": ["i-0a1b2c3d4e5f60003 (db-archive)"],
        },
        {
            "resource_id": "ec2-keypair/admin-jump",
            "resource_name": "admin-jump-key",
            "key_type": "ECDSA",
            "key_size": 384,
            "attached_to": ["i-0a1b2c3d4e5f60004 (jump-host)"],
        },
    ]

    tls_configs = [
        {
            "resource_id": "elbv2/app/prod-frontend/abc123",
            "resource_name": "prod-frontend-alb",
            "min_tls_version": "TLS 1.2",
            "cipher_suites": [
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
            ],
        },
        {
            "resource_id": "elbv2/app/legacy-api/def456",
            "resource_name": "legacy-api-elb",
            "min_tls_version": "TLS 1.0",
            "cipher_suites": [
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_RSA_WITH_RC4_128_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            ],
        },
        {
            "resource_id": "apigw/payments-api",
            "resource_name": "payments-api-gateway",
            "min_tls_version": "TLS 1.3",
            "cipher_suites": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ],
        },
        {
            "resource_id": "lb/internal/analytics",
            "resource_name": "analytics-internal-lb",
            "min_tls_version": "TLS 1.2",
            "cipher_suites": [
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            ],
        },
    ]

    rng.shuffle(certificates)
    rng.shuffle(ssh_keys)
    rng.shuffle(tls_configs)

    return {
        "certificates": certificates,
        "ssh_keys": ssh_keys,
        "tls_configs": tls_configs,
    }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_environment(inventory: dict) -> list[Finding]:
    findings: list[Finding] = []

    for cert in inventory.get("certificates", []):
        algo_label = cert["algorithm"]
        if cert.get("key_size"):
            algo_label += f"-{cert['key_size']}"
        result = classify_asymmetric_algorithm(cert["algorithm"], cert.get("key_size"))
        findings.append(Finding(
            asset_type="Certificate",
            resource_id=cert["resource_id"],
            resource_name=cert["resource_name"],
            detail=algo_label,
            extra={"issuer": cert.get("issuer"), "expires": cert.get("expires")},
            **result,
        ))

    for key in inventory.get("ssh_keys", []):
        algo_label = key["key_type"]
        if key.get("key_size"):
            algo_label += f"-{key['key_size']}"
        result = classify_asymmetric_algorithm(key["key_type"], key.get("key_size"))
        findings.append(Finding(
            asset_type="SSH Key",
            resource_id=key["resource_id"],
            resource_name=key["resource_name"],
            detail=algo_label,
            extra={"attached_to": key.get("attached_to", [])},
            **result,
        ))

    for tls in inventory.get("tls_configs", []):
        for suite in tls.get("cipher_suites", []):
            result = classify_cipher_suite(suite)
            findings.append(Finding(
                asset_type="TLS Config",
                resource_id=tls["resource_id"],
                resource_name=f"{tls['resource_name']} ({tls.get('min_tls_version', '?')})",
                detail=suite,
                extra={"min_tls_version": tls.get("min_tls_version")},
                **result,
            ))
        for group in tls.get("key_exchange_groups", []):
            result = classify_key_exchange_group(group)
            findings.append(Finding(
                asset_type="TLS Config",
                resource_id=tls["resource_id"],
                resource_name=f"{tls['resource_name']} ({tls.get('min_tls_version', '?')})",
                detail=f"key-exchange group: {group}",
                extra={"min_tls_version": tls.get("min_tls_version")},
                **result,
            ))

    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.SAFE: 3}


def generate_report_markdown(findings: list[Finding]) -> str:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])

    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    lines = []
    lines.append("# Quantum-Readiness Migration Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total assets scanned: **{len(findings)}**")
    lines.append(f"- Critical: **{counts[Severity.CRITICAL]}**")
    lines.append(f"- High: **{counts[Severity.HIGH]}**")
    lines.append(f"- Medium (quantum-weakened): **{counts[Severity.MEDIUM]}**")
    lines.append(f"- Safe / Quantum-resistant: **{counts[Severity.SAFE]}**")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Status | Asset Type | Resource | Detail | Recommendation |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings_sorted:
        lines.append(
            f"| {f.severity.value} | {f.status} | {f.asset_type} | "
            f"{f.resource_name} | {f.detail} | {f.recommendation} |"
        )
    lines.append("")

    lines.append("## Migration Plan")
    lines.append("")
    lines.append("Recommended phases, ordered by severity:")
    lines.append("")
    lines.append("1. **Critical** — assets vulnerable to both classical and quantum "
                  "attacks today (e.g. RSA-1024, DSA, RC4/3DES, plain RSA key exchange). "
                  "Rotate immediately.")
    lines.append("2. **High** — assets safe today but broken by a cryptographically "
                  "relevant quantum computer (RSA-2048+, ECDSA, ECDHE, Ed25519/X25519). "
                  "Plan migration to hybrid classical+PQC or pure PQC "
                  f"({PQC_SIGNATURE_RECOMMENDATION}, {PQC_KEM_RECOMMENDATION}) within your "
                  "organization's crypto-agility roadmap.")
    lines.append("3. **Medium** — symmetric algorithms weakened (not broken) by Grover's "
                  "algorithm (AES-128, 3DES). Upgrade to AES-256 opportunistically.")
    lines.append("4. **Safe** — already post-quantum or unaffected; no action required.")
    lines.append("")

    lines.append("## Detail by Asset")
    lines.append("")
    for f in findings_sorted:
        lines.append(f"### {f.asset_type}: {f.resource_name}")
        lines.append(f"- Resource ID: `{f.resource_id}`")
        lines.append(f"- Algorithm/Detail: `{f.detail}`")
        lines.append(f"- Status: **{f.status}** (Severity: {f.severity.value})")
        lines.append(f"- Reason: {f.reason}")
        lines.append(f"- Recommendation: {f.recommendation}")
        if f.extra:
            for k, v in f.extra.items():
                if v:
                    lines.append(f"- {k}: {v}")
        lines.append("")

    return "\n".join(lines)


def generate_report_json(findings: list[Finding]) -> str:
    data = []
    for f in findings:
        d = asdict(f)
        d["severity"] = f.severity.value
        data.append(d)

    counts = {sev.value: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    return json.dumps({"summary": counts, "findings": data}, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-mock", metavar="FILE",
                         help="Write a mock cloud inventory JSON file and exit.")
    parser.add_argument("--input", metavar="FILE",
                         help="Inventory JSON file to scan (use --generate-mock to create one).")
    parser.add_argument("--output", metavar="FILE", default="migration_report.md",
                         help="Report output path (default: migration_report.md).")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown",
                         help="Report format (default: markdown).")
    args = parser.parse_args()

    if args.generate_mock:
        inventory = generate_mock_environment()
        with open(args.generate_mock, "w", encoding="utf-8") as fh:
            json.dump(inventory, fh, indent=2)
        print(f"Mock inventory written to {args.generate_mock}")
        return

    if not args.input:
        print("Using built-in mock inventory (pass --input to scan a real inventory file).")
        inventory = generate_mock_environment()
    else:
        with open(args.input, "r", encoding="utf-8") as fh:
            inventory = json.load(fh)

    findings = scan_environment(inventory)

    if args.format == "json":
        report = generate_report_json(findings)
    else:
        report = generate_report_markdown(findings)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1
    print(f"Scanned {len(findings)} assets.")
    print(f"  Critical: {counts[Severity.CRITICAL]}  High: {counts[Severity.HIGH]}  "
          f"Medium: {counts[Severity.MEDIUM]}  Safe: {counts[Severity.SAFE]}")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
