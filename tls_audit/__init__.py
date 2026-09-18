"""tls_audit: a lightweight TLS/SSL configuration auditor.

Checks a list of domains against current TLS best practice: which
protocol versions they still accept, the cipher negotiated by
default, and certificate expiry / key strength.
"""

__version__ = "0.1.0"
