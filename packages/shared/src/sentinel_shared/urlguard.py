from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import dns.resolver


class ValidationErrorCodes:
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    INVALID_URL = "INVALID_URL"
    CREDENTIALS_IN_URL = "CREDENTIALS_IN_URL"
    LOCALHOST = "LOCALHOST"
    PRIVATE_TARGET = "PRIVATE_TARGET"
    METADATA_ENDPOINT = "METADATA_ENDPOINT"
    SUSPICIOUS_HOST = "SUSPICIOUS_HOST"
    NO_DNS_RECORDS = "NO_DNS_RECORDS"
    MIXED_RESOLVED_ADDRESSES = "MIXED_RESOLVED_ADDRESSES"


class TargetValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message


_ALLOWED_SCHEMES = {"http", "https"}
_REJECTED_SCHEMES = {
    "file", "ftp", "gopher", "javascript", "data", "ws", "wss", "blob", "mailto",
    "telnet", "ssh", "ldap", "sftp", "chrome", "resource", "view-source",
}

BLOCKED_HOST_SUFFIXES = (
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    "metadata.google.internal",
    "metadata.azure.com",
)

_DOTLESS = re.compile(r"^[0-9]+$", re.IGNORECASE)
_HEXISH = re.compile(r"^0x[0-9a-f]+(\.[0-9a-f]+)*$", re.IGNORECASE)
_OCTISH = re.compile(r"^0[0-7]?[0-7.]*$")

# Classification buckets used when deciding whether a target may be scanned.
NOT_PUBLIC_CLASSIFICATIONS = {
    "loopback",
    "link_local",
    "private",
    "multicast",
    "reserved",
    "unspecified",
    "private_internet",  # 100.64.0.0/10 CGNAT
}


@dataclass(frozen=True)
class ResolvedTarget:
    host: str
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    all_public: bool


def normalize_url(url: str) -> str:
    """Normalize an asset URL. Raises TargetValidationError for unsafe input."""
    if not url or not isinstance(url, str):
        raise TargetValidationError(ValidationErrorCodes.INVALID_URL, "URL is required.")

    url = url.strip()
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()

    if scheme in _REJECTED_SCHEMES:
        raise TargetValidationError(
            ValidationErrorCodes.UNSUPPORTED_SCHEME,
            f"Scheme '{scheme}:' is not allowed. Use http:// or https://.",
        )
    if scheme not in _ALLOWED_SCHEMES:
        # Common user mistake: "example.com" or "www.example.com/path"
        if scheme in ("", "localhost") and parsed.netloc == "":
            url = "https://" + url.lstrip("/")
            parsed = urlsplit(url)
            scheme = "https"
        else:
            raise TargetValidationError(
                ValidationErrorCodes.INVALID_URL,
                "URL must start with http:// or https://.",
            )

    if not parsed.netloc:
        raise TargetValidationError(ValidationErrorCodes.INVALID_URL, "URL has no host.")

    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise TargetValidationError(
            ValidationErrorCodes.CREDENTIALS_IN_URL,
            "URLs containing user info (user:pass@host) are not accepted.",
        )

    host = parsed.hostname
    if not host:
        raise TargetValidationError(ValidationErrorCodes.INVALID_URL, "URL has no host.")
    host = host.strip("[]").lower().rstrip(".")

    if not re.fullmatch(r"[a-z0-9._-]+", host) and not _looks_like_ipv6(host):
        raise TargetValidationError(
            ValidationErrorCodes.INVALID_URL,
            "Host contains characters that are not allowed.",
        )
    if "_" in host:
        raise TargetValidationError(
            ValidationErrorCodes.SUSPICIOUS_HOST,
            "Host contains an underscore, which is not valid in hostnames.",
        )
    if _DOTLESS.fullmatch(host):
        raise TargetValidationError(
            ValidationErrorCodes.SUSPICIOUS_HOST,
            "Numeric-only hostnames (decimal IPv4 encodings) are not allowed.",
        )
    if re.search(r"0x", host, re.IGNORECASE):
        raise TargetValidationError(
            ValidationErrorCodes.SUSPICIOUS_HOST,
            "Host uses a non-standard numeric encoding (hex/octal).",
        )
    if _HEXISH.fullmatch(host) or _OCTISH.fullmatch(host):
        raise TargetValidationError(
            ValidationErrorCodes.SUSPICIOUS_HOST,
            "Host uses a non-standard numeric encoding (hex/octal).",
        )
    if not _looks_like_ipv4(host) and not _looks_like_ipv6(host):
        # Domain-name sanity check, blocks things like "1.1.1.999"
        if not re.fullmatch(r"(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*", host):
            raise TargetValidationError(
                ValidationErrorCodes.INVALID_URL, "Host is not a valid domain name."
            )
        if host[-1] == "-":
            raise TargetValidationError(
                ValidationErrorCodes.INVALID_URL, "Host ends with a hyphen."
            )

    port = parsed.port
    if port is not None:
        if port < 1 or port > 65535:
            raise TargetValidationError(ValidationErrorCodes.INVALID_URL, "Port out of range.")
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

    path = parsed.path or "/"
    host_part = f"[{host}]" if _looks_like_ipv6(host) else host
    netloc = host_part + (f":{port}" if port is not None else "")
    normalized = urlunsplit((scheme, netloc, path, "", ""))
    return normalized


def _looks_like_ipv6(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return ":" in host


def _looks_like_ipv4(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))


def classify_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            # IPv6-mapped IPv4 addresses (::ffff:127.0.0.1) inherit their IPv4 fate
            return classify_address(mapped)
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link_local"
        if addr.is_multicast:
            return "multicast"
        if addr.is_private or addr.is_reserved:
            return "private" if addr.is_private else "reserved"
        if addr.is_unspecified:
            return "unspecified"
        return "public"
    if addr == ipaddress.ip_address("169.254.169.254") or addr in ipaddress.ip_network(
        "169.254.169.0/24"
    ):
        return "metadata"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_reserved:
        return "reserved"
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return "private_internet"
    if addr.is_private:
        return "private"
    return "public"


def is_host_allowed(
    host: str,
    allow_private: bool = False,
    classifications: tuple[str, ...] | None = None,
) -> tuple[bool, list[str]]:
    """Check whether a host string is allowed without DNS resolution."""
    host = (host or "").strip().strip("[]").lower().rstrip(".")
    bad: list[str] = []
    if not host:
        return False, ["empty host"]
    if _DOTLESS.fullmatch(host):
        bad.append("decimal-encoded IPv4")
    if _HEXISH.fullmatch(host):
        bad.append("hex-encoded address")
    if _OCTISH.fullmatch(host) and host not in ("0",):
        bad.append("octal-encoded address")
    lowered = host
    for suffix in BLOCKED_HOST_SUFFIXES:
        if lowered == suffix.strip(".") or lowered.endswith(suffix):
            bad.append(f"reserved host suffix '{suffix}'")
    if allow_private:
        return len(bad) == 0, bad
    if classifications:
        for c in classifications:
            if c in NOT_PUBLIC_CLASSIFICATIONS or c == "metadata":
                bad.append(f"resolves to {c} address")
    return len(bad) == 0, bad


def resolve_host(host: str, timeout: float = 10.0) -> ResolvedTarget:
    """Resolve a hostname and validate all returned addresses.

    All-or-nothing rule: if ANY resolved address is private/reserved the whole
    host is rejected. This defeats partially-rebinding answers that return one
    public and one private A record.
    """
    host = (host or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        raise TargetValidationError(ValidationErrorCodes.INVALID_URL, "Empty host.")

    literal_ip: ipaddress.IPv6Address | ipaddress.IPv4Address | None = None
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        addresses = [literal_ip]
        classifications = [classify_address(literal_ip)]
        explicitly_allowed, bad = is_host_allowed(host, allow_private=True)
        if not explicitly_allowed:
            raise TargetValidationError(
                ValidationErrorCodes.SUSPICIOUS_HOST, "Unsupported literal address form."
            )
    else:
        allowed, bad = is_host_allowed(host, allow_private=True)
        if not allowed:
            raise TargetValidationError(
                ValidationErrorCodes.SUSPICIOUS_HOST,
                "Host is not allowed: " + "; ".join(bad),
            )
        addresses = []
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.lifetime = timeout
            resolver.timeout = timeout
            answers = resolver.resolve(host, "A")
            addresses.extend(ipaddress.ip_address(r.address) for r in answers if r.address)
        except dns.resolver.NoAnswer:
            pass
        except Exception as exc:  # NXDOMAIN etc
            raise TargetValidationError(
                ValidationErrorCodes.NO_DNS_RECORDS,
                f"DNS resolution failed for '{host}': {type(exc).__name__}",
            ) from exc
        if not addresses:
            raise TargetValidationError(
                ValidationErrorCodes.NO_DNS_RECORDS, f"No addresses resolve for '{host}'."
            )
        classifications = [classify_address(a) for a in addresses]

    all_public = all(c == "public" for c in classifications)
    return ResolvedTarget(host=host, addresses=tuple(addresses), all_public=all_public)


def assert_url_scannable(url: str, allow_private: bool = False) -> tuple[str, ResolvedTarget]:
    """Normalize URL + resolve host + enforce SSRF rules. Returns (normalized, target)."""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    allowed, bad = is_host_allowed(host, allow_private=allow_private)
    if not allowed:
        if "localhost" in " ".join(bad) or "*.localhost" in " ".join(bad):
            raise TargetValidationError(
                ValidationErrorCodes.LOCALHOST, "Loopback targets are not allowed."
            )
        raise TargetValidationError(
            ValidationErrorCodes.SUSPICIOUS_HOST, "Host is not allowed: " + "; ".join(bad)
        )
    target = resolve_host(host)
    if not allow_private and not target.all_public:
        cset = sorted({classify_address(a) for a in target.addresses})
        code = ValidationErrorCodes.METADATA_ENDPOINT if "metadata" in cset else (
            ValidationErrorCodes.PRIVATE_TARGET
        )
        raise TargetValidationError(
            code, "The target resolves to a non-public network address ("
            + ", ".join(cset) + ")."
        )
    return normalized, target


def resolve_and_validate_socket(host: str, port: int, timeout: float = 10.0) -> list[str]:
    """Resolve via socket.getaddrinfo (matches platform behavior of httpx) and enforce rules."""
    results = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    addresses: list[str] = []
    for info in results:
        addr = info[4][0]
        addresses.append(str(addr))
    classes = [classify_address(ipaddress.ip_address(a)) for a in addresses]
    if any(c != "public" for c in classes):
        raise TargetValidationError(
            ValidationErrorCodes.PRIVATE_TARGET,
            "Resolved address is not on a public network.",
        )
    return addresses
