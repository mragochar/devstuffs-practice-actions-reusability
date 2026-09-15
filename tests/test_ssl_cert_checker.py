"""Tests for ssl_cert_checker.

Run these from the repo root so Python can find the module:

    python3 -m pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import ssl_cert_checker as scc


CERT_TIME_FMT = "%b %d %H:%M:%S %Y GMT"


def _cert_time(dt: datetime) -> str:
    """Render a datetime the way a real certificate's notBefore/notAfter
    fields are formatted, so ssl.cert_time_to_seconds() can parse it."""
    return dt.astimezone(timezone.utc).strftime(CERT_TIME_FMT)


def _fake_cert(
    not_before: datetime, not_after: datetime, common_name: str = "example.com"
) -> dict:
    return {
        "subject": ((("commonName", common_name),),),
        "issuer": ((("commonName", "Test CA"),),),
        "notBefore": _cert_time(not_before),
        "notAfter": _cert_time(not_after),
    }


def _fake_ssl_context(cert: dict) -> MagicMock:
    """Stands in for the real SSLContext that check_host() builds. Its
    wrap_socket() hands back a fake TLS socket whose getpeercert() returns
    the certificate dict we choose — no real TLS handshake ever happens."""
    ssock = MagicMock()
    ssock.__enter__.return_value = ssock
    ssock.__exit__.return_value = False
    ssock.getpeercert.return_value = cert

    ctx = MagicMock()
    ctx.wrap_socket.return_value = ssock
    return ctx


def _fake_raw_socket() -> MagicMock:
    raw = MagicMock()
    raw.__enter__.return_value = raw
    raw.__exit__.return_value = False
    return raw


@patch("ssl_cert_checker._default_context")
@patch("ssl_cert_checker.socket.create_connection")
@patch("ssl_cert_checker.socket.getaddrinfo")
def test_check_host_reports_ok_for_a_healthy_certificate(
    mock_getaddrinfo, mock_create_connection, mock_default_context
):
    mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
    mock_create_connection.return_value = _fake_raw_socket()

    not_before = datetime.now(timezone.utc) - timedelta(days=10)
    not_after = datetime.now(timezone.utc) + timedelta(days=60)
    mock_default_context.return_value = _fake_ssl_context(
        _fake_cert(not_before, not_after)
    )

    result = scc.check_host("example.com")

    assert result.status == "ok"
    assert 58 <= result.days_remaining <= 60


@patch("ssl_cert_checker._default_context")
@patch("ssl_cert_checker.socket.create_connection")
@patch("ssl_cert_checker.socket.getaddrinfo")
def test_check_host_reports_expired_for_a_lapsed_certificate(
    mock_getaddrinfo, mock_create_connection, mock_default_context
):
    mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
    mock_create_connection.return_value = _fake_raw_socket()

    not_before = datetime.now(timezone.utc) - timedelta(days=400)
    not_after = datetime.now(timezone.utc) - timedelta(days=20)
    mock_default_context.return_value = _fake_ssl_context(
        _fake_cert(not_before, not_after)
    )

    result = scc.check_host("stale.example.com")

    assert result.status == "expired"
    assert result.days_remaining < 0


@patch("ssl_cert_checker.socket.getaddrinfo")
def test_check_host_reports_error_when_dns_fails(mock_getaddrinfo):
    import socket as real_socket

    mock_getaddrinfo.side_effect = real_socket.gaierror("Name or service not known")

    result = scc.check_host("does-not-exist.invalid")

    assert result.status == "error"
    assert "DNS resolution failed" in result.message


def _canned_result(status: str, days_remaining: int) -> scc.CertResult:
    """A pre-built CertResult for testing main()'s exit-code logic directly,
    without going anywhere near check_host() or the network."""
    return scc.CertResult(
        host="example.com",
        port=443,
        status=status,
        subject="CN=example.com",
        issuer="CN=Test CA",
        not_before="",
        not_after="",
        days_remaining=days_remaining,
        message="canned result for exit-code testing",
    )


@patch("ssl_cert_checker.check_host")
def test_main_exits_zero_when_everything_is_healthy(mock_check_host, capsys):
    mock_check_host.return_value = _canned_result("ok", days_remaining=90)

    assert scc.main(["example.com", "--days", "30"]) == 0


@patch("ssl_cert_checker.check_host")
def test_main_exits_one_when_inside_the_warning_window(mock_check_host, capsys):
    mock_check_host.return_value = _canned_result("ok", days_remaining=5)

    assert scc.main(["example.com", "--days", "30"]) == 1


@patch("ssl_cert_checker.check_host")
def test_main_exits_one_when_expired(mock_check_host, capsys):
    mock_check_host.return_value = _canned_result("expired", days_remaining=-12)

    assert scc.main(["example.com", "--days", "30"]) == 1


@patch("ssl_cert_checker.check_host")
def test_main_exits_two_when_unreachable(mock_check_host, capsys):
    mock_check_host.return_value = _canned_result("error", days_remaining=-9999)

    assert scc.main(["example.com", "--days", "30"]) == 2
