from __future__ import annotations

import datetime
import http.server
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from sentinel_scanner.http.client import _is_hostname_mismatch_error
from sentinel_scanner.http.tls import (
    _aia_ca_issuers_url,
    _der_to_pem,
    _fetch_der_from_aia,
    _is_self_signed,
)


def _build_certs(tmp_path: Path) -> tuple[bytes, bytes]:
    """Return (leaf DER, ca PEM) with the leaf advertising an AIA CA Issuers URL."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel Test CA")])
    now = datetime.datetime.now(datetime.UTC)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("http://127.0.0.1/ca.pem"),
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return leaf.public_bytes(serialization.Encoding.DER), ca_path


def test_aia_url_extraction_and_pem_roundtrip(tmp_path: Path) -> None:
    leaf_der, ca_pem = _build_certs(tmp_path)
    assert _aia_ca_issuers_url(leaf_der) == "http://127.0.0.1/ca.pem"

    pem = _der_to_pem(leaf_der)
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    roundtrip = ssl.PEM_cert_to_DER_cert(pem)
    assert roundtrip == leaf_der
    assert _is_self_signed(leaf_der) is False
    assert _is_self_signed(
        x509.load_pem_x509_certificate(ca_pem.read_bytes()).public_bytes(
            serialization.Encoding.DER)
    ) is True


def test_no_aia_extension(tmp_path: Path) -> None:
    leaf_der, _ca = _build_certs(tmp_path)
    leaf = x509.load_der_x509_certificate(leaf_der)
    stripped = (
        x509.CertificateBuilder()
        .subject_name(leaf.subject)
        .issuer_name(leaf.issuer)
        .public_key(leaf.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(leaf.not_valid_before)
        .not_valid_after(leaf.not_valid_after)
        .sign(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)
    assert _aia_ca_issuers_url(stripped) is None


def test_fetch_der_from_aia_pem_and_der(tmp_path: Path) -> None:
    _leaf_der, ca_pem = _build_certs(tmp_path)
    pem_bytes = ca_pem.read_bytes()
    ca_cert = x509.load_pem_x509_certificate(pem_bytes)
    der_bytes = ca_cert.public_bytes(serialization.Encoding.DER)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_GET(self) -> None:
            payload = pem_bytes if self.path.endswith(".pem") else der_bytes
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(payload)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        fetched_pem = _fetch_der_from_aia(f"http://127.0.0.1:{port}/ca.pem")
        fetched_der = _fetch_der_from_aia(f"http://127.0.0.1:{port}/ca.der")
    finally:
        server.shutdown()
        thread.join()
    assert fetched_pem == der_bytes
    assert fetched_der == der_bytes


def test_hostname_mismatch_classification() -> None:
    # Real-world error shape (python ssl): verifies chain-first, then name.
    mismatch = ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "Hostname mismatch, certificate is not valid for www.exams.host. "
        "(_ssl.c:1010)"
    )
    chain = ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "unable to get local issuer certificate (_ssl.c:1010)"
    )
    assert _is_hostname_mismatch_error(mismatch) is True
    assert _is_hostname_mismatch_error(chain) is False
    # Cause-chain walking: httpx ConnectError wrapping is the live shape.
    wrapped = Exception("wrapped")
    wrapped.__cause__ = mismatch
    assert _is_hostname_mismatch_error(wrapped) is True
    assert _is_hostname_mismatch_error(None) is False
    assert _is_hostname_mismatch_error(OSError("no ssl here")) is False
    # Lowercase variant of the verify_message wording.
    alt = ssl.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] "
                       "certificate is not valid for 'www.host'")
    assert _is_hostname_mismatch_error(alt) is True
