"""Strict destination URL validation — syntax only, no network.

``parse_destination`` turns an untrusted URL string into a canonical
``(scheme, host, port)`` triple. It performs **syntactic validation
only** and deliberately does NOT:

- resolve DNS (so it cannot protect against DNS rebinding on its own),
- authorize the destination (that is ``policy.py``'s job),
- check transport availability (that is the capability registry's job),
- prove the destination is reachable or safe (no SSRF claim is made).

Threat model
------------
Attacker goal: smuggle a forbidden destination past validation using
parser confusion — userinfo tricks (``http://trusted@evil/``), ambiguous
IP spellings (``0x7f.0.0.1``, octal), percent-encoded hostnames,
backslashes, control characters, or scheme confusion.

Defenses in this module:

- userinfo (``username``/``password``/``@`` in authority) is rejected
  outright — the largest parser-confusion class is eliminated, not
  interpreted;
- IP literals are parsed strictly with :mod:`ipaddress`, which rejects
  octal/hex/ambiguous forms; the canonical compressed form is kept;
- DNS names must pass ``normalize_hostname`` (ASCII-only, no wildcards,
  no ports/paths); percent signs are rejected so encoded hostnames
  cannot slip through;
- backslashes, whitespace, and control characters are rejected;
- ports must be explicit ints in 1–65535 or a known scheme default.

Special-use addresses (loopback, private, link-local, multicast,
reserved, unspecified) are **classified, not rejected**: this module
validates syntax; the *policy* decides what is allowed. Classification
properties let callers and policies make that decision explicitly.
A DNS name that has not been resolved reports ``False`` for every
address property — an unresolved name is not an address.

ASCII-only hostnames are preserved from the v0.1 policy contract:
internationalized names must be supplied as A-labels (punycode).
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from egressweave.errors import DestinationValidationError, PolicyValidationError
from egressweave.policy import normalize_hostname

#: Schemes accepted when the caller does not supply an allowlist.
DEFAULT_SCHEMES: tuple[str, ...] = ("http", "https")

#: Well-known default ports. Schemes without an entry require an
#: explicit port in the URL.
SCHEME_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

_SCHEME_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."
)

#: Hostnames made solely of IP-notation characters. If such a name fails
#: strict :mod:`ipaddress` parsing it is ambiguous — some network stacks
#: (e.g. ``inet_aton``) would still interpret it as an address — so it
#: must be rejected, never treated as a DNS name.
_IP_LIKE = re.compile(r"^[0-9a-fA-FxX.:]+$")


def _check_schemes(schemes: object, *, where: str) -> tuple[str, ...]:
    if not isinstance(schemes, (tuple, list)) or not schemes:
        raise DestinationValidationError(where, "must be a non-empty tuple/list")
    out: list[str] = []
    for s in schemes:
        if not isinstance(s, str) or not s:
            raise DestinationValidationError(where, "scheme must be a non-empty str")
        low = s.lower()
        if any(c not in _SCHEME_TOKEN_CHARS for c in low):
            raise DestinationValidationError(where, f"invalid scheme: {s!r}")
        out.append(low)
    return tuple(out)


@dataclass(frozen=True)
class Destination:
    """A validated network destination: scheme, host, and port.

    ``host`` is canonical: lowercased DNS name (trailing dot stripped)
    or compressed IP literal. ``is_ip_literal`` tells which one.
    """

    scheme: str
    host: str
    port: int
    is_ip_literal: bool

    @property
    def _parsed_ip(self) -> IPv4Address | IPv6Address | None:
        if not self.is_ip_literal:
            return None
        return ipaddress.ip_address(self.host)

    @property
    def is_loopback(self) -> bool:
        """True for 127.0.0.0/8 and ::1."""
        ip = self._parsed_ip
        return ip.is_loopback if ip is not None else False

    @property
    def is_private(self) -> bool:
        """True for RFC 1918 / ULA ranges."""
        ip = self._parsed_ip
        return ip.is_private if ip is not None else False

    @property
    def is_link_local(self) -> bool:
        """True for 169.254.0.0/16 and fe80::/10."""
        ip = self._parsed_ip
        return ip.is_link_local if ip is not None else False

    @property
    def is_multicast(self) -> bool:
        ip = self._parsed_ip
        return ip.is_multicast if ip is not None else False

    @property
    def is_reserved(self) -> bool:
        ip = self._parsed_ip
        return ip.is_reserved if ip is not None else False

    @property
    def is_unspecified(self) -> bool:
        """True for 0.0.0.0 and ::."""
        ip = self._parsed_ip
        return ip.is_unspecified if ip is not None else False

    @property
    def is_global(self) -> bool:
        """True when the address looks publicly routable.

        This is a syntactic classification, not a reachability proof.
        """
        ip = self._parsed_ip
        return ip.is_global if ip is not None else False


def parse_destination(
    url: object,
    *,
    allowed_schemes: tuple[str, ...] | list[str] | None = None,
) -> Destination:
    """Strictly validate ``url`` and return its canonical destination.

    Raises :class:`DestinationValidationError` for anything malformed,
    ambiguous, or outside the scheme allowlist. Never returns a partial
    destination.
    """
    where = "url"
    if not isinstance(url, str):
        raise DestinationValidationError(where, "must be str")
    if not url.strip():
        raise DestinationValidationError(where, "must not be empty")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise DestinationValidationError(
            where, "contains whitespace or control characters"
        )
    if "\\" in url:
        raise DestinationValidationError(where, "backslashes are not allowed")

    schemes = (
        _check_schemes(allowed_schemes, where="allowed_schemes")
        if allowed_schemes is not None
        else DEFAULT_SCHEMES
    )

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise DestinationValidationError(where, f"unparseable URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if not scheme:
        raise DestinationValidationError(where, "scheme is required")
    if scheme not in schemes:
        raise DestinationValidationError(where, f"scheme {scheme!r} not allowed")

    # Userinfo is rejected outright: "http://trusted@evil/" must never
    # be interpreted as host "trusted".
    if parts.username is not None or parts.password is not None:
        raise DestinationValidationError(where, "userinfo is not allowed")
    if "@" in parts.netloc:
        raise DestinationValidationError(where, "userinfo is not allowed")

    raw_host = parts.hostname
    if not raw_host:
        raise DestinationValidationError(where, "host is required")
    if "%" in raw_host:
        # urlsplit does not decode the hostname; a percent-encoded host
        # is never a valid DNS name — reject, don't interpret.
        raise DestinationValidationError(
            where, "percent-encoded hostnames are not allowed"
        )

    try:
        port = parts.port
    except ValueError as exc:
        raise DestinationValidationError(where, f"invalid port: {exc}") from exc
    if port is None:
        default = SCHEME_DEFAULT_PORTS.get(scheme)
        if default is None:
            raise DestinationValidationError(
                where, f"scheme {scheme!r} has no default port; port is required"
            )
        port = default
    if not 1 <= port <= 65535:
        raise DestinationValidationError(where, f"port out of range: {port}")

    try:
        ip = ipaddress.ip_address(raw_host)
    except ValueError:
        ip = None
    if ip is not None:
        return Destination(
            scheme=scheme,
            host=ip.compressed,
            port=port,
            is_ip_literal=True,
        )
    if _IP_LIKE.match(raw_host):
        # Ambiguous: e.g. "0x7f.0.0.1", "0177.0.0.1", "2130706433".
        # Strict parsing failed, but a lenient resolver might still read
        # this as an address. Fail closed instead of treating it as DNS.
        # (Known limitation: all-hex DNS names like "dead.beef" are also
        # rejected; they are vanishingly rare and the safe default wins.)
        raise DestinationValidationError(
            "url.host",
            f"ambiguous IP-like hostname rejected: {raw_host!r}",
        )
    try:
        host = normalize_hostname(raw_host)
    except PolicyValidationError as exc:
        raise DestinationValidationError(
            "url.host", f"invalid hostname: {exc.reason}"
        ) from exc
    return Destination(
        scheme=scheme,
        host=host,
        port=port,
        is_ip_literal=False,
    )
