import pytest

from sentinel_shared.urlguard import (
    TargetValidationError,
    ValidationErrorCodes,
    assert_url_scannable,
    classify_address,
    is_host_allowed,
    normalize_url,
)
from sentinel_shared.versioning import compare_versions, is_below


class TestNormalizeUrl:
    def test_adds_scheme(self):
        assert normalize_url("Example.com") == "https://example.com/"

    def test_strips_default_port(self):
        assert normalize_url("http://example.com:80/") == "http://example.com/"
        assert normalize_url("https://example.com:443/x") == "https://example.com/x"

    def test_rejects_forbidden_schemes(self):
        for bad in ["ftp://a", "file:///etc/passwd", "gopher://a", "javascript:alert(1)",
                    "data:text/html,x", "ws://a"]:
            with pytest.raises(TargetValidationError) as ei:
                normalize_url(bad)
            assert ei.value.code == ValidationErrorCodes.UNSUPPORTED_SCHEME

    def test_rejects_credentials(self):
        with pytest.raises(TargetValidationError) as ei:
            normalize_url("http://user:pass@example.com")
        assert ei.value.code == ValidationErrorCodes.CREDENTIALS_IN_URL

    def test_rejects_decimal_ipv4(self):
        with pytest.raises(TargetValidationError) as ei:
            normalize_url("http://2130706433/")
        assert ei.value.code == ValidationErrorCodes.SUSPICIOUS_HOST

    def test_rejects_hex_ipv4(self):
        with pytest.raises(TargetValidationError):
            normalize_url("http://0x7f.0x0.0x0.0x1/")

    def test_rejects_underscore_host(self):
        with pytest.raises(TargetValidationError):
            normalize_url("http://bad_host.example.com")

    def test_ipv6_allowed_shape(self):
        assert normalize_url("http://[2001:4860:4860::8888]/x") == "http://[2001:4860:4860::8888]/x"


class TestClassify:
    @pytest.mark.parametrize("ip,expected", [
        ("127.0.0.1", "loopback"),
        ("10.0.0.5", "private"),
        ("172.16.1.1", "private"),
        ("192.168.1.1", "private"),
        ("169.254.1.1", "link_local"),
        ("169.254.169.254", "metadata"),
        ("224.0.0.5", "multicast"),
        ("100.64.0.1", "private_internet"),
        ("8.8.8.8", "public"),
        ("::1", "loopback"),
        ("::ffff:127.0.0.1", "loopback"),
        ("fe80::1", "link_local"),
        ("fc00::1", "private"),
        ("2606:4700::1", "public"),
    ])
    def test_classifications(self, ip, expected):
        import ipaddress
        assert classify_address(ipaddress.ip_address(ip)) == expected


class TestIsHostAllowed:
    def test_blocks_localhost(self):
        ok, _reasons = is_host_allowed("localhost")
        assert not ok

    def test_blocks_dotless_decimal(self):
        assert not is_host_allowed("1697668006")[0]

    def test_public_domain_ok(self):
        assert is_host_allowed("example.com")[0]


class TestVersion:
    def test_semver_not_lexicographic(self):
        assert compare_versions("8.4.9", "8.4.27") == -1
        assert compare_versions("8.4.27", "8.4.9") == 1
        assert compare_versions("8.10.0", "8.9.0") == 1
        assert compare_versions("8.2.35", "8.2.35") == 0

    def test_is_below(self):
        assert is_below("8.4.26", "8.4.27")
        assert not is_below("8.4.27", "8.4.27")
        assert not is_below("8.5.0", "8.4.27")


@pytest.mark.parametrize("url,code", [
    ("http://127.0.0.1/", ValidationErrorCodes.PRIVATE_TARGET),
    ("http://10.0.0.1/", ValidationErrorCodes.PRIVATE_TARGET),
    ("http://192.168.1.10/", ValidationErrorCodes.PRIVATE_TARGET),
    ("http://169.254.169.254/", ValidationErrorCodes.METADATA_ENDPOINT),
    ("http://localhost/", ValidationErrorCodes.LOCALHOST),
    ("http://2130706433/", ValidationErrorCodes.SUSPICIOUS_HOST),
])
def test_assert_url_scannable_violations(url, code):
    with pytest.raises(TargetValidationError) as ei:
        assert_url_scannable(url)
    assert ei.value.code == code
