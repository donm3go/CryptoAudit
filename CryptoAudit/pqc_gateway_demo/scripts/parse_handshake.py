#!/usr/bin/env python3
"""
Parse an `openssl s_client -msg -debug` transcript from the PQC gateway
demo and turn it into:

  1. A human-readable handshake summary (handshake_report.md)
  2. A TLS-config inventory fragment compatible with ../../quantum_audit.py,
     so the result can be merged into inventory.json and re-scanned.

Usage:
    python parse_handshake.py logs/client_handshake.log logs/selected_group.txt \
        --output handshake_report.md --inventory-fragment tls_config_fragment.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PQC_GROUP_PATTERN = re.compile(r"(MLKEM|KYBER)", re.IGNORECASE)


def parse_transcript(text: str) -> dict:
    result = {
        "protocol": None,
        "cipher": None,
        "server_temp_key": None,
        "verify_return_code": None,
        "raw_matches": {},
    }

    proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.MULTILINE)
    if proto:
        result["protocol"] = proto.group(1)

    cipher = re.search(r"^\s*Cipher\s*:\s*(\S+)", text, re.MULTILINE) \
        or re.search(r"Cipher is (\S+)", text)
    if cipher:
        result["cipher"] = cipher.group(1)

    temp_key = re.search(r"^Server Temp Key:\s*(.+)$", text, re.MULTILINE) \
        or re.search(r"^Negotiated TLS1\.3 group:\s*(.+)$", text, re.MULTILINE)
    if temp_key:
        result["server_temp_key"] = temp_key.group(1).strip()

    verify = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", text)
    if verify:
        result["verify_return_code"] = {
            "code": int(verify.group(1)),
            "message": verify.group(2),
        }

    return result


def build_report(parsed: dict, group: str, raw_log_path: str) -> tuple[str, dict]:
    temp_key = parsed.get("server_temp_key") or ""
    is_pqc_group = bool(PQC_GROUP_PATTERN.search(temp_key)) or bool(PQC_GROUP_PATTERN.search(group))
    handshake_ok = parsed.get("protocol") is not None and parsed.get("cipher") is not None

    status = "Quantum-Safe (key exchange)" if (handshake_ok and is_pqc_group) else "Quantum-Vulnerable (key exchange)"

    lines = []
    lines.append("# PQC Gateway Handshake Report")
    lines.append("")
    lines.append("## Result")
    lines.append("")
    lines.append(f"- Handshake completed: **{'YES' if handshake_ok else 'NO'}**")
    lines.append(f"- Negotiated protocol: `{parsed.get('protocol')}`")
    lines.append(f"- Negotiated cipher: `{parsed.get('cipher')}`")
    lines.append(f"- Requested hybrid KEM group: `{group}`")
    lines.append(f"- Server Temp Key (negotiated key-exchange group): `{temp_key}`")
    if parsed.get("verify_return_code"):
        vrc = parsed["verify_return_code"]
        lines.append(f"- Certificate verify return code: `{vrc['code']} ({vrc['message']})` "
                      f"(non-zero is expected — server cert is self-signed)")
    lines.append(f"- Key-exchange status: **{status}**")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    if handshake_ok and is_pqc_group:
        lines.append(
            "The TLS 1.3 handshake completed successfully using a **hybrid "
            f"post-quantum key exchange group ({temp_key or group})**. This combines "
            "a classical ECDHE share with an ML-KEM/Kyber share — an eavesdropper "
            "recording this session today cannot recover the shared secret even "
            "with a future cryptographically relevant quantum computer, because "
            "breaking it requires breaking *both* the classical ECDH share *and* "
            "the ML-KEM share."
        )
        lines.append("")
        lines.append(
            "Note: the **server certificate's signature algorithm is still "
            "classical ECDSA P-256** (see `certs/server.crt`). Key exchange and "
            "certificate-signature migrations are independent — this gateway has "
            "completed phase 1 (key exchange) but still needs phase 2 "
            "(PQC/hybrid certificate signatures, e.g. ML-DSA) to fully close the "
            "'harvest now, decrypt later' gap for authentication."
        )
    else:
        lines.append(
            "The handshake either failed or did not negotiate a hybrid PQC "
            "key-exchange group. Check that the OpenSSL build includes "
            "`oqsprovider` (or is OpenSSL 3.5+ with native ML-KEM groups) and "
            f"that `{raw_log_path}` shows the requested group `{group}` in the "
            "supported_groups extension."
        )
    lines.append("")

    fragment = {
        "resource_id": "pqc-gateway-demo/local",
        "resource_name": "pqc-gateway-demo (simulated API Gateway)",
        "min_tls_version": parsed.get("protocol") or "unknown",
        "cipher_suites": [parsed.get("cipher")] if parsed.get("cipher") else [],
        "key_exchange_groups": [temp_key or group],
    }

    return "\n".join(lines), fragment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcript", help="Path to client_handshake.log")
    parser.add_argument("group_file", help="Path to selected_group.txt")
    parser.add_argument("--output", default="handshake_report.md", help="Markdown report output path")
    parser.add_argument("--inventory-fragment", default="tls_config_fragment.json",
                         help="JSON fragment to merge into inventory.json's tls_configs")
    args = parser.parse_args()

    text = Path(args.transcript).read_text(encoding="utf-8", errors="replace")
    group_line = Path(args.group_file).read_text(encoding="utf-8", errors="replace").strip()
    group = group_line.split()[-1] if group_line else "unknown"

    parsed = parse_transcript(text)
    report, fragment = build_report(parsed, group, args.transcript)

    Path(args.output).write_text(report, encoding="utf-8")
    Path(args.inventory_fragment).write_text(json.dumps(fragment, indent=2), encoding="utf-8")

    print(report)
    print(f"\nReport written to {args.output}")
    print(f"Inventory fragment written to {args.inventory_fragment}")


if __name__ == "__main__":
    main()
