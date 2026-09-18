"""Network-facing TLS probes: protocol support, negotiated cipher and
certificate details for a single host. Kept deliberately separate from
grading.py so the scoring rules can be unit-tested without a socket.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_PROTOCOLS_TO_PROBE = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")


@dataclass
class CertificateInfo:
    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    san: list[str] = field(default_factory=list)
    key_type: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    trusted: bool | None = None
    trust_error: str | None = None


@dataclass
class DomainResult:
    domain: str
    port: int
    reachable: bool = False
    error: str | None = None
    protocols: dict[str, bool] = field(default_factory=dict)
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
    certificate: CertificateInfo | None = None


def _probe_single_protocol(host: str, port: int, version: str, timeout: float) -> bool:
    """Return True if the server completes a handshake pinned to exactly
    this protocol version. The client's security level is dropped to 0
    so a deliberately weak/legacy protocol isn't rejected before we find
    out what the server itself would do."""
    attr = version.replace(".", "_")
    tls_version = getattr(ssl.TLSVersion, attr, None)
    if tls_version is None:
        return False

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass

    try:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (ValueError, OSError):
        return False

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, socket.timeout):
        return False


def _probe_protocols(host: str, port: int, timeout: float) -> dict[str, bool]:
    return {
        version: _probe_single_protocol(host, port, version, timeout)
        for version in _PROTOCOLS_TO_PROBE
    }


def _default_handshake(host: str, port: int, timeout: float):
    """Negotiate the way a normal client would: highest mutually
    supported protocol, default cipher preference, no forced downgrade."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()  # (name, protocol, secret_bits) or None
                protocol = tls.version()
                der_cert = tls.getpeercert(binary_form=True)
                cipher_name = cipher[0] if cipher else None
                return protocol, cipher_name, der_cert, None
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return None, None, None, exc


def _check_trust(host: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, getattr(exc, "verify_message", None) or str(exc)
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return None, str(exc)


def _parse_certificate(der_cert: bytes) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der_cert)
    info = CertificateInfo()
    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.not_before = cert.not_valid_before_utc
    info.not_after = cert.not_valid_after_utc
    info.signature_algorithm = cert.signature_algorithm_oid._name

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        info.san = []

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        info.key_type = "RSA"
        info.key_bits = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info.key_type = "EC"
        info.key_bits = public_key.curve.key_size
    else:
        info.key_type = type(public_key).__name__
        info.key_bits = None

    return info


def scan_domain(domain: str, port: int = 443, timeout: float = 5.0) -> DomainResult:
    result = DomainResult(domain=domain, port=port)

    protocol, cipher_name, der_cert, handshake_error = _default_handshake(domain, port, timeout)
    if der_cert is None:
        result.error = str(handshake_error) if handshake_error else "Handshake failed."
        result.reachable = False
        return result

    result.reachable = True
    result.negotiated_protocol = protocol
    result.negotiated_cipher = cipher_name
    result.protocols = _probe_protocols(domain, port, timeout)
    if protocol:
        result.protocols[protocol] = True

    try:
        result.certificate = _parse_certificate(der_cert)
    except Exception as exc:  # noqa: BLE001 - surface, don't crash a whole run
        result.error = f"Certificate could not be parsed: {exc}"

    trusted, trust_error = _check_trust(domain, port, timeout)
    if result.certificate:
        result.certificate.trusted = trusted
        result.certificate.trust_error = trust_error

    return result
