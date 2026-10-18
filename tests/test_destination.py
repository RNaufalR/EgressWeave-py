"""Adversarial tests for destination URL validation.

Every test here is pure string parsing. No test in this module opens a
network connection, resolves DNS, or contacts any external target.
"""

from __future__ import annotations

import pytest

from egressweave.destination import Destination, parse_destination
from egressweave.errors import DestinationValidationError


def test_basic_https_defaults() -> None:
    d = parse_destination("https://example.com/")
    assert d == Destination(
        scheme="https", host="example.com", port=443, is_ip_literal=False
    )


def test_http_default_port() -> None:
    assert parse_destination("http://example.com/").port == 80


def test_explicit_port() -> None:
    assert parse_destination("https://example.com:8443/path?q=1").port == 8443


def test_scheme_and_host_case_normalized() -> None:
    d = parse_destination("HTTP://EXAMPLE.COM/")
    assert (d.scheme, d.host) == ("http", "example.com")


def test_trailing_dot_stripped() -> None:
    assert parse_destination("https://example.com./").host == "example.com"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "not a url",
        "http://",
        "://example.com/",
        "//example.com/path",  # scheme-relative
        "example.com/path",  # no scheme
        "http:///path",
        "http://?q=1",
    ],
)
def test_malformed_urls_rejected(url: str) -> None:
    with pytest.raises(DestinationValidationError):
        parse_destination(url)


def test_non_string_rejected() -> None:
    for bad in (None, 123, b"https://example.com/", ["https://example.com/"]):
        with pytest.raises(DestinationValidationError):
            parse_destination(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "url",
    [
        "http://user@example.com/",
        "http://user:pass@example.com/",
        "http://user:pass@example.com:8080/",
        "https://trusted.example.com@evil.example.com/",
        "http://@example.com/",
    ],
)
def test_userinfo_rejected(url: str) -> None:
    # Parser confusion between userinfo and host must fail closed.
    with pytest.raises(DestinationValidationError, match="userinfo"):
        parse_destination(url)


@pytest.mark.parametrize(
    "url", ["ftp://example.com/", "javascript:alert(1)", "data:text/plain,hi"]
)
def test_disallowed_scheme_rejected(url: str) -> None:
    with pytest.raises(DestinationValidationError, match="scheme"):
        parse_destination(url)


def test_custom_scheme_allowlist() -> None:
    d = parse_destination("ws://example.com:8080/", allowed_schemes=("ws",))
    assert (d.scheme, d.port) == ("ws", 8080)
    with pytest.raises(DestinationValidationError):
        parse_destination("http://example.com/", allowed_schemes=("ws",))


def test_scheme_without_default_port_requires_explicit() -> None:
    with pytest.raises(DestinationValidationError, match="port is required"):
        parse_destination("ws://example.com/", allowed_schemes=("ws",))


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:0/",
        "http://example.com:65536/",
        "http://example.com:abc/",
        "http://example.com:-1/",
        "http://example.com:80:80/",
    ],
)
def test_invalid_ports_rejected(url: str) -> None:
    with pytest.raises(DestinationValidationError, match="port"):
        parse_destination(url)


@pytest.mark.parametrize(
    ("url", "host", "checks"),
    [
        ("http://127.0.0.1/", "127.0.0.1", {"is_loopback": True, "is_global": False}),
        ("http://10.0.0.1/", "10.0.0.1", {"is_private": True, "is_global": False}),
        ("http://192.168.1.1/", "192.168.1.1", {"is_private": True}),
        ("http://172.16.5.4/", "172.16.5.4", {"is_private": True}),
        ("http://169.254.10.20/", "169.254.10.20", {"is_link_local": True}),
        ("http://8.8.8.8/", "8.8.8.8", {"is_global": True, "is_private": False}),
        ("http://0.0.0.0/", "0.0.0.0", {"is_unspecified": True}),
        ("http://[::1]/", "::1", {"is_loopback": True}),
        ("http://[fe80::1]/", "fe80::1", {"is_link_local": True}),
        ("http://[::ffff:127.0.0.1]/", "::ffff:7f00:1", {"is_loopback": False}),
        (
            "http://[2001:db8::1]/",
            "2001:db8::1",
            {"is_private": True, "is_global": False},
        ),
    ],
)
def test_ip_literals_classified(url: str, host: str, checks: dict) -> None:
    d = parse_destination(url)
    assert d.is_ip_literal is True
    assert d.host == host
    for prop, expected in checks.items():
        assert getattr(d, prop) is expected, prop


@pytest.mark.parametrize(
    "url",
    [
        "http://0x7f.0.0.1/",  # hex octet
        "http://0177.0.0.1/",  # octal octet
        "http://2130706433/",  # single integer form
        "http://0x7f000001/",
    ],
)
def test_ambiguous_ipv4_forms_rejected(url: str) -> None:
    # ipaddress is strict; ambiguous forms must not become 127.0.0.1.
    with pytest.raises(DestinationValidationError):
        parse_destination(url)


def test_percent_encoded_hostname_rejected() -> None:
    with pytest.raises(DestinationValidationError, match="percent-encoded"):
        parse_destination("http://%65xample.com/")


def test_backslash_rejected() -> None:
    with pytest.raises(DestinationValidationError, match="backslash"):
        parse_destination("http://example.com\\@evil.com/")


def test_control_characters_and_whitespace_rejected() -> None:
    urls = ("http://example.com/\n", " http://example.com/", "http://exam ple.com/")
    for url in urls:
        with pytest.raises(DestinationValidationError, match="whitespace"):
            parse_destination(url)


def test_unicode_hostname_rejected_ascii_only_preserved() -> None:
    # The v0.1 ASCII-only rule is unchanged: IDN must arrive as A-label.
    with pytest.raises(DestinationValidationError):
        parse_destination("http://münchen.de/")
    d = parse_destination("http://xn--mnchen-3ya.de/")
    assert d.host == "xn--mnchen-3ya.de"
    assert d.is_ip_literal is False


def test_wildcard_hostname_rejected() -> None:
    with pytest.raises(DestinationValidationError):
        parse_destination("http://*.example.com/")


def test_dns_name_reports_no_address_properties() -> None:
    d = parse_destination("https://example.com/")
    assert d.is_ip_literal is False
    assert not any(
        [
            d.is_loopback,
            d.is_private,
            d.is_link_local,
            d.is_multicast,
            d.is_reserved,
            d.is_unspecified,
            d.is_global,
        ]
    )


def test_destination_is_immutable() -> None:
    d = parse_destination("https://example.com/")
    with pytest.raises(AttributeError):
        d.host = "evil.com"  # type: ignore[misc]


def test_ipv6_canonical_form() -> None:
    d = parse_destination("http://[2001:0DB8:0000::0001]/")
    assert d.host == "2001:db8::1"
    assert d.is_ip_literal is True


def test_fragment_and_query_ignored_for_destination() -> None:
    d = parse_destination("https://example.com:443/path?q=1#frag")
    assert (d.host, d.port) == ("example.com", 443)
