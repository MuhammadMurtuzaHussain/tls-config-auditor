"""Command-line entry point: read a domain list, scan each host
concurrently, grade the results against best practice, and print (and
optionally export) a report."""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from . import grading, report
from .scanner import DomainResult, scan_domain

DEFAULT_DOMAINS_FILE = Path("domains.txt")


def _load_domains(args: argparse.Namespace) -> list[str]:
    if args.domains:
        return args.domains
    path = Path(args.domains_file) if args.domains_file else DEFAULT_DOMAINS_FILE
    if not path.exists():
        raise SystemExit(
            f"No domains given and {path} does not exist. Pass domains as "
            "arguments or point --domains-file at a list."
        )
    domains = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    if not domains:
        raise SystemExit(f"{path} contains no domains.")
    return domains


def _to_row(result: DomainResult, warn_days: int, crit_days: int) -> dict:
    if not result.reachable:
        return {
            "domain": result.domain,
            "port": result.port,
            "reachable": False,
            "error": result.error,
            "overall_status": grading.UNKNOWN,
            "issues": [result.error or "Host unreachable."],
        }

    protocol_grade = grading.grade_protocols(result.protocols)
    cipher_grade = grading.grade_cipher(
        result.negotiated_cipher, result.negotiated_protocol
    )

    cert = result.certificate
    trust_issues: list[str] = []
    if cert:
        cert_grade = grading.grade_certificate(
            cert.not_after,
            cert.not_before,
            cert.key_type,
            cert.key_bits,
            warn_days=warn_days,
            crit_days=crit_days,
        )
        cert_days_remaining = (
            (cert.not_after - datetime.now(timezone.utc)).days
            if cert.not_after
            else None
        )
        if cert.trusted is False:
            trust_issues = [f"Certificate chain not trusted: {cert.trust_error}"]
    else:
        cert_grade = grading.GradeResult(grading.UNKNOWN, ["No certificate observed."])
        cert_days_remaining = None

    statuses = [protocol_grade.status, cipher_grade.status, cert_grade.status]
    if trust_issues:
        statuses.append(grading.FAIL)
    issues = (
        protocol_grade.issues + cipher_grade.issues + cert_grade.issues + trust_issues
    )

    return {
        "domain": result.domain,
        "port": result.port,
        "reachable": True,
        "negotiated_protocol": result.negotiated_protocol,
        "negotiated_cipher": result.negotiated_cipher,
        "protocols_supported": [k for k, v in result.protocols.items() if v],
        "cert_subject": cert.subject if cert else None,
        "cert_issuer": cert.issuer if cert else None,
        "cert_not_after": cert.not_after if cert else None,
        "cert_days_remaining": cert_days_remaining,
        "cert_key_type": cert.key_type if cert else None,
        "cert_key_bits": cert.key_bits if cert else None,
        "cert_trusted": cert.trusted if cert else None,
        "overall_status": grading.overall_status(statuses),
        "issues": issues,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-audit",
        description="Check a list of domains' TLS configuration against current best practice.",
    )
    parser.add_argument(
        "domains", nargs="*", help="Domains to check (space separated)."
    )
    parser.add_argument(
        "--domains-file",
        help="Path to a file with one domain per line (default: domains.txt).",
    )
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Per-connection timeout in seconds."
    )
    parser.add_argument(
        "--warn-days",
        type=int,
        default=30,
        help="Warn when a cert expires within N days.",
    )
    parser.add_argument(
        "--crit-days",
        type=int,
        default=14,
        help="Fail when a cert expires within N days.",
    )
    parser.add_argument(
        "--workers", type=int, default=8, help="Concurrent domains to scan."
    )
    parser.add_argument(
        "--json", metavar="PATH", help="Also write the full report as JSON to PATH."
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colour in the table."
    )
    parser.add_argument(
        "--strict", action="store_true", help="Exit non-zero on WARN as well as FAIL."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    domains = _load_domains(args)

    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_domain, domain, args.port, args.timeout): domain
            for domain in domains
        }
        for future in as_completed(futures):
            result = future.result()
            rows.append(_to_row(result, args.warn_days, args.crit_days))

    order = {domain: i for i, domain in enumerate(domains)}
    rows.sort(key=lambda r: order.get(r["domain"], 0))

    print(report.render_table(rows, use_color=not args.no_color))

    if args.json:
        Path(args.json).write_text(report.render_json(rows))
        print(f"\nFull report written to {args.json}")

    worst = grading.overall_status([r["overall_status"] for r in rows])
    if worst == grading.FAIL:
        return 1
    if worst == grading.WARN and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
