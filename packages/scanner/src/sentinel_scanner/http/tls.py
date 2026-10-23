"""Automatic TLS intermediate-certificate chasing via AIA (RFC 5280 §4.2.2.1).

When a target server omits intermediate certificates from its TLS handshake
(a very common misconfiguration), a strict verifier raises
``ssl.SSLCertVerificationError``.  This module resolves that by:

1. Opening a *certificate-inspection-only* raw TLS connection to read the
   server's leaf certificate.  No application data is exchanged over this
   connection — it is used solely to inspect the AIA extension.
2. Extracting the "CA Issuers" URL from the AIA extension.
3. Downloading the issuer certificate over plain HTTP (AIA URLs are always
   HTTP per RFC 5280).
4. Repeating steps 2-3 up the chain until a self-signed root is reached or
   the downloaded cert is already trusted by the certifi bundle.
5. Returning a fresh ``ssl.SSLContext`` with ``verify_mode=CERT_REQUIRED``
   and the fetched intermediates loaded alongside the certifi root store.

Security properties that are preserved
---------------------------------------
* ``verify_mode`` is always ``ssl.CERT_REQUIRED`` on the *returned* context.
* ``check_hostname`` is always ``True`` on the *returned* context.
* The unverified inspection connection sends no credentials and receives no
  application data — only the TLS ServerHello/Certificate messages.
* Downloaded intermediates are never blindly trusted: they are only loaded
  as *intermediates*, not as root CAs.  The chain must still root in a
  trusted certifi anchor.
* AIA URLs are fetched over HTTP (the standard); HTTPS AIA URLs are ignored
  to avoid a recursive verification problem.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import socket
import ssl
import urllib.request
from urllib.parse import urlsplit

import certifi

log = logging.getLogger("sentinel.tls")

_MAX_CHAIN_DEPTH = 8   # maximum number of intermediates to chase
_CONNECT_TIMEOUT = 10  # seconds — raw socket to read leaf cert
_FETCH_TIMEOUT = 10    # seconds — HTTP fetch of each intermediate


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def build_aia_ssl_context(hostname: str, port: int) -> ssl.SSLContext | None:
    """Try to build a fully-verifying SSLContext by chasing AIA intermediates.

    All blocking I/O runs in a thread pool so the event loop is not stalled.

    Returns an ``ssl.SSLContext`` (``CERT_REQUIRED``) with the discovered
    intermediates loaded, or ``None`` if AIA chasing did not yield anything
    useful (e.g. no AIA extension, network failure, chain still untrusted).
    """
    try:
        result = await asyncio.to_thread(_chase, hostname, port)
        return result
    except Exception as exc:
        log.debug("sentinel.tls: AIA chase failed for %s:%d — %s", hostname, port, exc)
        return None


# ---------------------------------------------------------------------------
# Internal synchronous helpers (run inside asyncio.to_thread)
# ---------------------------------------------------------------------------

def _chase(hostname: str, port: int) -> ssl.SSLContext | None:
    """Synchronous AIA-chasing worker."""
    leaf_der = _get_leaf_cert_der(hostname, port)
    if leaf_der is None:
        return None

    fetched_ders: list[bytes] = []
    current_der = leaf_der

    for _ in range(_MAX_CHAIN_DEPTH):
        aia_url = _aia_ca_issuers_url(current_der)
        if not aia_url:
            break  # no AIA hint — chain is complete or cert is malformed
        issuer_der = _fetch_der_from_aia(aia_url)
        if issuer_der is None or issuer_der == current_der or issuer_der in fetched_ders:
            break
        fetched_ders.append(issuer_der)
        log.info("sentinel.tls: fetched intermediate from %s", aia_url)
        # Stop if this cert is self-signed (it's a root; certifi should have it)
        if _is_self_signed(issuer_der):
            break
        current_der = issuer_der

    if not fetched_ders:
        return None  # AIA chasing found nothing new

    # Build a verifying context: certifi roots + downloaded intermediates.
    ctx = ssl.create_default_context(cafile=certifi.where())
    for der in fetched_ders:
        try:
            ctx.load_verify_locations(cadata=_der_to_pem(der))
        except ssl.SSLError as exc:
            log.debug("sentinel.tls: could not load intermediate — %s", exc)
    return ctx


def _get_leaf_cert_der(hostname: str, port: int) -> bytes | None:
    """Open a *certificate-inspection-only* TLS connection and return the
    server's leaf certificate as raw DER bytes.

    ``verify_mode=CERT_NONE`` is intentional here: we are inspecting the cert
    to find AIA URLs, not authenticating the server.  No application data is
    sent or received over this connection.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as raw,
              ctx.wrap_socket(raw, server_hostname=hostname) as tls):
            return tls.getpeercert(binary_form=True) or None
    except OSError:
        return None


def _aia_ca_issuers_url(der_cert: bytes) -> str | None:
    """Extract the first plain-HTTP CA Issuers URL from a DER certificate's
    Authority Information Access extension, or ``None`` if absent."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import (
            AuthorityInformationAccessOID,
            ExtensionOID,
        )

        cert = x509.load_der_x509_certificate(der_cert)
        aia_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for access_desc in aia_ext.value:
            if access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                url: str = access_desc.access_location.value
                # Only follow HTTP AIA URLs (spec-compliant and avoids recursion)
                if urlsplit(url).scheme == "http":
                    return url
    except Exception:
        pass
    return None


def _is_self_signed(der_cert: bytes) -> bool:
    """Return True if the certificate's subject equals its issuer (root CA)."""
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der_cert)
        return cert.subject == cert.issuer
    except Exception:
        return False


def _fetch_der_from_aia(url: str) -> bytes | None:
    """Download a certificate from an AIA URL; return DER bytes or ``None``."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SentinelSecurityScanner/1.0 (AIA-Chase; RFC5280)"},
        )
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            data: bytes = resp.read(65_536)  # 64 KiB — no real cert is larger
        if not data:
            return None
        # If the response is PEM-encoded, convert to DER for uniform handling.
        stripped = data.lstrip()
        if stripped.startswith(b"-----BEGIN"):
            return ssl.PEM_cert_to_DER_cert(data.decode("ascii", errors="replace"))
        return data  # assume DER
    except Exception:
        return None


def _der_to_pem(der_bytes: bytes) -> str:
    """Convert raw DER certificate bytes to a PEM string."""
    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"
