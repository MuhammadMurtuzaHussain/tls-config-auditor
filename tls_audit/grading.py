"""Pure grading logic: best-practice rules for protocols, ciphers and
certificates. No network I/O lives here, which is what makes it
unit-testable without touching a socket.

Baseline references:
  - RFC 8996: TLS 1.0 and TLS 1.1 are deprecated and MUST NOT be used.
  - Mozilla "Intermediate" TLS configuration: minimum TLS 1.2, prefer 1.3.
  - NIST SP 800-52 Rev. 2: servers SHALL support TLS 1.2 and SHOULD
    support TLS 1.3; SHALL NOT support TLS 1.0/1.1 for new systems.
  - CA/Browser Forum Baseline Requirements: public certificates must not
    exceed 398 days' validity; RSA keys must be >= 2048 bits.
  - NIST SP 800-57: minimum key-strength recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

PASS, WARN, FAIL, UNKNOWN = "PASS", "WARN", "FAIL", "UNKNOWN"

_STATUS_PRIORITY = {FAIL: 3, WARN: 2, UNKNOWN: 1, PASS: 0}

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
RECOMMENDED_MINIMUM = "TLSv1.2"
RECOMMENDED_PROTOCOL = "TLSv1.3"

WEAK_CIPHER_SUBSTRINGS = (
    "NULL",
    "EXPORT",
    "RC4",
    "RC2",
    "DES",
    "3DES",
    "MD5",
    "ADH",
    "AECDH",
    "PSK",
    "SEED",
    "IDEA",
    "ANON",
)

MIN_RSA_KEY_BITS = 2048
MIN_EC_KEY_BITS = 224
MAX_CERT_VALIDITY_DAYS = 398  # CA/Browser Forum Baseline Requirements


@dataclass
class GradeResult:
    status: str
    issues: list[str] = field(default_factory=list)


def overall_status(statuses: list[str]) -> str:
    """Roll several statuses up into one, worst-first."""
    if not statuses:
        return UNKNOWN
    return max(statuses, key=lambda s: _STATUS_PRIORITY.get(s, 0))


def grade_protocols(supported: dict[str, bool]) -> GradeResult:
    issues: list[str] = []
    enabled = {proto for proto, ok in supported.items() if ok}

    deprecated_enabled = sorted(enabled & DEPRECATED_PROTOCOLS)
    if deprecated_enabled:
        issues.append(
            f"Deprecated protocol(s) still accepted: {', '.join(deprecated_enabled)} "
            "(RFC 8996 - must not be offered)."
        )

    if not enabled:
        issues.append("No TLS protocol version could be negotiated.")
        return GradeResult(FAIL, issues)

    if deprecated_enabled:
        return GradeResult(FAIL, issues)

    if RECOMMENDED_PROTOCOL not in enabled:
        issues.append(
            f"{RECOMMENDED_PROTOCOL} is not offered; server falls back to "
            f"{RECOMMENDED_MINIMUM} only."
        )
        return GradeResult(WARN, issues)

    return GradeResult(PASS, issues)


def grade_cipher(cipher_name: str | None, protocol: str | None) -> GradeResult:
    if not cipher_name:
        return GradeResult(UNKNOWN, ["No cipher could be determined."])

    issues: list[str] = []
    upper = cipher_name.upper()
    hit = [tag for tag in WEAK_CIPHER_SUBSTRINGS if tag in upper]
    if hit:
        issues.append(
            f"Negotiated cipher '{cipher_name}' matches weak pattern(s): {', '.join(hit)}."
        )
        return GradeResult(FAIL, issues)

    if protocol == "TLSv1.2" and "GCM" not in upper and "CHACHA20" not in upper:
        issues.append(
            f"'{cipher_name}' is CBC-mode on TLS 1.2; prefer an AEAD suite "
            "(GCM / ChaCha20-Poly1305)."
        )
        return GradeResult(WARN, issues)

    return GradeResult(PASS, issues)


def grade_certificate(
    not_after: datetime | None,
    not_before: datetime | None,
    key_type: str | None,
    key_bits: int | None,
    warn_days: int,
    crit_days: int,
    now: datetime | None = None,
) -> GradeResult:
    issues: list[str] = []
    now = now or datetime.now(timezone.utc)

    if not_after is None:
        return GradeResult(UNKNOWN, ["Certificate expiry could not be read."])

    days_remaining = (not_after - now).days

    if days_remaining < 0:
        issues.append(f"Certificate expired {abs(days_remaining)} day(s) ago.")
        status = FAIL
    elif days_remaining <= crit_days:
        issues.append(
            f"Certificate expires in {days_remaining} day(s) (<= {crit_days})."
        )
        status = FAIL
    elif days_remaining <= warn_days:
        issues.append(
            f"Certificate expires in {days_remaining} day(s) (<= {warn_days})."
        )
        status = WARN
    else:
        status = PASS

    if not_before and now < not_before:
        issues.append("Certificate is not yet valid.")
        status = overall_status([status, FAIL])

    if not_before and not_after:
        validity_days = (not_after - not_before).days
        if validity_days > MAX_CERT_VALIDITY_DAYS:
            issues.append(
                f"Validity period is {validity_days} days, exceeding the "
                f"{MAX_CERT_VALIDITY_DAYS}-day CA/Browser Forum maximum."
            )
            status = overall_status([status, WARN])

    if key_type and key_bits:
        if key_type.upper() == "RSA" and key_bits < MIN_RSA_KEY_BITS:
            issues.append(f"RSA key is {key_bits} bits (< {MIN_RSA_KEY_BITS}).")
            status = overall_status([status, FAIL])
        elif key_type.upper() in {"EC", "ECDSA"} and key_bits < MIN_EC_KEY_BITS:
            issues.append(f"EC key is {key_bits} bits (< {MIN_EC_KEY_BITS}).")
            status = overall_status([status, FAIL])

    return GradeResult(status, issues)
