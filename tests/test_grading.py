from datetime import datetime, timedelta, timezone

from tls_audit import grading


def test_protocols_pass_when_tls13_supported():
    result = grading.grade_protocols({"TLSv1.2": True, "TLSv1.3": True})
    assert result.status == grading.PASS


def test_protocols_warn_when_only_tls12():
    result = grading.grade_protocols({"TLSv1.2": True, "TLSv1.3": False})
    assert result.status == grading.WARN


def test_protocols_fail_when_deprecated_supported():
    result = grading.grade_protocols({"TLSv1": True, "TLSv1.2": True, "TLSv1.3": True})
    assert result.status == grading.FAIL
    assert "TLSv1" in result.issues[0]


def test_protocols_fail_when_nothing_negotiates():
    result = grading.grade_protocols({"TLSv1.2": False, "TLSv1.3": False})
    assert result.status == grading.FAIL


def test_cipher_fail_on_rc4():
    result = grading.grade_cipher("ECDHE-RSA-RC4-SHA", "TLSv1.2")
    assert result.status == grading.FAIL


def test_cipher_pass_on_modern_aead():
    result = grading.grade_cipher("TLS_AES_256_GCM_SHA384", "TLSv1.3")
    assert result.status == grading.PASS


def test_cipher_warn_on_cbc_tls12():
    result = grading.grade_cipher("ECDHE-RSA-AES256-SHA384", "TLSv1.2")
    assert result.status == grading.WARN


def test_cipher_unknown_when_missing():
    result = grading.grade_cipher(None, None)
    assert result.status == grading.UNKNOWN


def test_certificate_fail_when_expired():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_after = now - timedelta(days=3)
    not_before = not_after - timedelta(days=90)
    result = grading.grade_certificate(
        not_after, not_before, "RSA", 2048, warn_days=30, crit_days=14, now=now
    )
    assert result.status == grading.FAIL


def test_certificate_warn_when_near_expiry():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_after = now + timedelta(days=20)
    not_before = not_after - timedelta(days=90)
    result = grading.grade_certificate(
        not_after, not_before, "RSA", 2048, warn_days=30, crit_days=14, now=now
    )
    assert result.status == grading.WARN


def test_certificate_pass_when_healthy():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_after = now + timedelta(days=200)
    not_before = now - timedelta(days=10)
    result = grading.grade_certificate(
        not_after, not_before, "RSA", 2048, warn_days=30, crit_days=14, now=now
    )
    assert result.status == grading.PASS


def test_certificate_fail_on_weak_rsa_key():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_after = now + timedelta(days=200)
    not_before = now - timedelta(days=10)
    result = grading.grade_certificate(
        not_after, not_before, "RSA", 1024, warn_days=30, crit_days=14, now=now
    )
    assert result.status == grading.FAIL


def test_certificate_warn_on_long_validity_period():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_before = now - timedelta(days=10)
    not_after = now + timedelta(days=500)
    result = grading.grade_certificate(
        not_after, not_before, "RSA", 2048, warn_days=30, crit_days=14, now=now
    )
    assert result.status == grading.WARN


def test_overall_status_worst_first():
    assert (
        grading.overall_status([grading.PASS, grading.WARN, grading.FAIL])
        == grading.FAIL
    )
    assert grading.overall_status([grading.PASS, grading.WARN]) == grading.WARN
    assert grading.overall_status([grading.PASS, grading.PASS]) == grading.PASS
    assert grading.overall_status([]) == grading.UNKNOWN
