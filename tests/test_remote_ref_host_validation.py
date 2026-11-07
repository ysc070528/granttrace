"""--remote-ref-host values must be exact host names that a $ref URL can match.

The allowlist is compared with the host of each remote $ref URL. A value with a
scheme, port, path, userinfo or wildcard can never equal such a host, so it used
to be accepted silently and then authorized nothing.
"""

from __future__ import annotations

import io
import ipaddress
import unittest
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.remote_refs import (
    InvalidRemoteRefHostError,
    RemoteRefConfig,
    RemoteRefError,
    RemoteRefFetcher,
    RemoteRefNotAllowedHostError,
    normalize_remote_ref_host,
)

SPEC = str(Path(__file__).resolve().parents[1] / "openapi.json")


class TestNormalizeRemoteRefHost(unittest.TestCase):
    def test_accepts_exact_host_names(self) -> None:
        cases = {
            "schemas.example.com": "schemas.example.com",
            "  Schemas.Example.COM ": "schemas.example.com",
            "localhost": "localhost",
            "example.com.": "example.com.",
            "xn--bcher-kva.example": "xn--bcher-kva.example",
            "my_host.internal-zone.example": "my_host.internal-zone.example",
            "a" * 63 + ".example": "a" * 63 + ".example",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_remote_ref_host(value), expected)

    def test_ip_literals_use_canonical_form(self) -> None:
        cases = {
            "93.184.216.34": "93.184.216.34",
            "2001:DB8:0:0::1": "2001:db8::1",
            "[2001:db8::1]": "2001:db8::1",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_remote_ref_host(value), expected)

    def test_rejects_values_that_can_never_match(self) -> None:
        cases = {
            "": "empty",
            "   ": "empty",
            "https://schemas.example.com": "scheme",
            "HTTPS://schemas.example.com/": "scheme",
            "schemas.example.com:443": "port",
            "schemas.example.com:8443": "port",
            "[2001:db8::1]:443": "port",
            "schemas.example.com/openapi.yaml": "path",
            "schemas.example.com?x=1": "path",
            "schemas.example.com#frag": "path",
            "schemas.example.com\\x": "path",
            "*.example.com": "wildcard",
            "user@schemas.example.com": "credentials",
            "schemas example.com": "whitespace",
            "schemas.example.com\tx": "whitespace",
            "\x1b[31mschemas.example.com": "control",
            "bücher.example": "ASCII",
            "-bad.example.com": "not a valid host name",
            "bad-.example.com": "not a valid host name",
            "a..b.example": "not a valid host name",
            ".example.com": "not a valid host name",
            "example.com..": "not a valid host name",
            "a" * 64 + ".example": "not a valid host name",
            ("a" * 60 + ".") * 5: "not a valid host name",
            "[not-an-ipv6]": "not a valid IPv6",
            "[93.184.216.34]": "not a valid IPv6",
            "2001:db8::1]": "not a valid IPv6",
            "[2001:db8::1": "not a valid IPv6",
            "[[2001:db8::1]]": "not a valid IPv6",
        }
        for value, fragment in cases.items():
            with self.subTest(value=value):
                with self.assertRaises(InvalidRemoteRefHostError) as ctx:
                    normalize_remote_ref_host(value)
                self.assertIn(fragment, str(ctx.exception))

    def test_non_ascii_hint_names_idna_form(self) -> None:
        with self.assertRaises(InvalidRemoteRefHostError) as ctx:
            normalize_remote_ref_host("bücher.example")
        self.assertIn("xn--bcher-kva.example", str(ctx.exception))

    def test_rejects_non_string(self) -> None:
        for value in (None, 123, b"schemas.example.com"):
            with self.subTest(value=value):
                with self.assertRaises(InvalidRemoteRefHostError):
                    normalize_remote_ref_host(value)  # type: ignore[arg-type]

    def test_error_is_a_remote_ref_error(self) -> None:
        self.assertTrue(issubclass(InvalidRemoteRefHostError, RemoteRefError))

    def test_error_message_does_not_echo_raw_control_characters(self) -> None:
        with self.assertRaises(InvalidRemoteRefHostError) as ctx:
            normalize_remote_ref_host("evil\x1b[2J.example")
        self.assertNotIn("\x1b", str(ctx.exception))


class TestRemoteRefConfigHosts(unittest.TestCase):
    def test_create_normalizes_hosts(self) -> None:
        config = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=[" Schemas.Example.com ", "[2001:DB8::1]"],
        )
        self.assertEqual(config.remote_ref_hosts, frozenset({"schemas.example.com", "2001:db8::1"}))

    def test_create_rejects_invalid_host(self) -> None:
        for value in ("https://schemas.example.com", "schemas.example.com:443", ""):
            with self.subTest(value=value):
                with self.assertRaises(InvalidRemoteRefHostError):
                    RemoteRefConfig.create(allow_remote_refs=True, remote_ref_hosts=[value])

    def test_ipv6_url_matches_regardless_of_textual_form(self) -> None:
        config = RemoteRefConfig.create(allow_remote_refs=True, remote_ref_hosts=["2001:db8::1"])
        fetcher = RemoteRefFetcher(config)
        for url in ("https://[2001:db8::1]/s.yaml", "https://[2001:DB8:0:0::1]/s.yaml"):
            with self.subTest(url=url):
                hostname, path, port = fetcher.validate_ref_url(url)
                self.assertEqual((path, port), ("/s.yaml", 443))
                self.assertEqual(ipaddress.ip_address(hostname), ipaddress.ip_address("2001:db8::1"))

    def test_host_names_still_match_exactly(self) -> None:
        config = RemoteRefConfig.create(allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"])
        fetcher = RemoteRefFetcher(config)
        self.assertEqual(
            fetcher.validate_ref_url("https://SCHEMAS.example.com/a.yaml"),
            ("schemas.example.com", "/a.yaml", 443),
        )
        for url in ("https://example.com/a.yaml", "https://x.schemas.example.com/a.yaml"):
            with self.subTest(url=url):
                with self.assertRaises(RemoteRefNotAllowedHostError):
                    fetcher.validate_ref_url(url)


class TestCliRemoteRefHost(unittest.TestCase):
    def _run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err), \
                patch("core.remote_refs.socket.getaddrinfo",
                      side_effect=AssertionError("no DNS lookup expected")):
            ret = main(list(argv))
        return ret, out.getvalue(), err.getvalue()

    def test_cli_rejects_url_like_host_before_any_work(self) -> None:
        for value, fragment in (
            ("https://schemas.example.com", "scheme"),
            ("schemas.example.com:443", "port"),
            ("*.example.com", "wildcard"),
            ("", "empty"),
        ):
            with self.subTest(value=value):
                ret, out, err = self._run(
                    "--spec", SPEC, "--dry-run",
                    "--allow-remote-refs", "--remote-ref-host", value,
                )
                self.assertEqual(ret, 2)
                self.assertIn("--remote-ref-host", err)
                self.assertIn(fragment, err)
                self.assertIn(repr(value), err)
                # Rejected before the banner, like other argument errors.
                self.assertEqual(out, "")

    def test_cli_names_the_bad_value_among_several(self) -> None:
        ret, _, err = self._run(
            "--spec", SPEC, "--dry-run", "--allow-remote-refs",
            "--remote-ref-host", "schemas.example.com",
            "--remote-ref-host", "cdn.example.org/models",
        )
        self.assertEqual(ret, 2)
        self.assertIn("'cdn.example.org/models'", err)
        self.assertNotIn("'schemas.example.com'", err)

    def test_cli_escapes_control_characters_in_bad_value(self) -> None:
        ret, _, err = self._run(
            "--spec", SPEC, "--dry-run", "--allow-remote-refs",
            "--remote-ref-host", "evil\x1b[2J.example",
        )
        self.assertEqual(ret, 2)
        self.assertNotIn("\x1b", err)
        self.assertIn("\\x1b", err)

    def test_cli_accepts_valid_host(self) -> None:
        ret, _, err = self._run(
            "--spec", SPEC, "--dry-run",
            "--allow-remote-refs", "--remote-ref-host", "Schemas.Example.com",
        )
        self.assertEqual(ret, 0, err)
        self.assertNotIn("--remote-ref-host", err)


if __name__ == "__main__":
    unittest.main()
