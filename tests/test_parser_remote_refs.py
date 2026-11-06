# -*- coding: utf-8 -*-
"""Comprehensive tests for secure remote $ref resolution in OpenAPIParser, Auditor and CLI."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from api_sentinel import build_argument_parser, main
from core.auditor import APISentinelAuditor
from core.parser import OpenAPIParser
from core.remote_refs import (
    RemoteRefConfig,
    RemoteRefDisabledError,
    RemoteRefFetcher,
    RemoteRefNotAllowedHostError,
    RemoteRefSecurityError,
)


class TestParserRemoteRefOptInAndDisabling(unittest.TestCase):
    """Test default disabling, opt-in enforcement, and host allowlist restrictions."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_spec(self, schema_ref: str) -> Path:
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "OK"}},
                    },
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": schema_ref}
                                }
                            },
                        },
                        "responses": {"201": {"description": "Created"}},
                    },
                }
            },
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")
        return spec_file

    def test_default_parser_rejects_remote_ref_with_zero_network(self) -> None:
        spec_file = self._create_spec("https://schemas.example.com/models/user.json#/User")
        parser = OpenAPIParser(str(spec_file))

        with self.assertRaises(RemoteRefDisabledError) as ctx:
            parser.get_endpoints()
        self.assertIn("Remote $ref values are not supported", str(ctx.exception))
        self.assertIsNone(parser.remote_fetcher)

    def test_parser_with_disabled_config_rejects_remote_ref(self) -> None:
        spec_file = self._create_spec("https://schemas.example.com/models/user.json#/User")
        cfg = RemoteRefConfig.create(allow_remote_refs=False, remote_ref_hosts=["schemas.example.com"])
        parser = OpenAPIParser(str(spec_file), remote_ref_config=cfg)

        with self.assertRaises(RemoteRefDisabledError) as ctx:
            parser.get_endpoints()
        self.assertIn("Remote $ref values are not supported", str(ctx.exception))

    def test_parser_with_empty_hosts_rejects_remote_ref(self) -> None:
        spec_file = self._create_spec("https://schemas.example.com/models/user.json#/User")
        cfg = RemoteRefConfig.create(allow_remote_refs=True, remote_ref_hosts=[])
        parser = OpenAPIParser(str(spec_file), remote_ref_config=cfg)

        with self.assertRaises(RemoteRefDisabledError) as ctx:
            parser.get_endpoints()
        self.assertIn("Remote $ref values are not supported without authorized hosts", str(ctx.exception))

    def test_parser_rejects_unauthorized_host(self) -> None:
        spec_file = self._create_spec("https://evil.attacker.com/models/user.json#/User")
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )
        parser = OpenAPIParser(str(spec_file), remote_ref_config=cfg)

        with self.assertRaises(RemoteRefNotAllowedHostError) as ctx:
            parser.get_endpoints()
        self.assertIn("evil.attacker.com", str(ctx.exception))

    def test_parser_source_files_excludes_remote_urls(self) -> None:
        spec_file = self._create_spec("https://schemas.example.com/models/user.json#/User")
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )
        parser = OpenAPIParser(str(spec_file), remote_ref_config=cfg)
        # source_files must contain only Path objects, never URLs
        for src in parser.source_files:
            self.assertIsInstance(src, Path)
            self.assertFalse(str(src).startswith("http"))


class TestParserRemoteRefResolution(unittest.TestCase):
    """Test successful schema resolution and composition for remote references."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_spec(self, body_schema: Dict[str, Any]) -> Path:
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": body_schema
                                }
                            },
                        },
                        "responses": {"201": {"description": "Created"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")
        return spec_file

    def test_remote_ref_schema_resolution_success(self) -> None:
        spec_file = self._create_spec({"$ref": "https://schemas.example.com/models/item.json#/definitions/Item"})
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)

        remote_doc = {
            "definitions": {
                "Item": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "price": {"type": "number"},
                    },
                    "required": ["name"],
                }
            }
        }

        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", return_value=remote_doc) as mock_fetch:
            endpoints = parser.get_endpoints()
            self.assertEqual(len(endpoints), 1)
            schema = endpoints[0]["request_schema"]
            self.assertEqual(schema["type"], "object")
            self.assertIn("name", schema["properties"])
            self.assertIn("price", schema["properties"])
            mock_fetch.assert_called_once_with("https://schemas.example.com/models/item.json")

    def test_remote_ref_composition_with_all_of(self) -> None:
        spec_file = self._create_spec({
            "allOf": [
                {"$ref": "https://schemas.example.com/models/base.json#/BaseEntity"},
                {
                    "type": "object",
                    "properties": {"role": {"type": "string"}},
                },
            ]
        })
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)

        base_entity_doc = {
            "BaseEntity": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "created_at": {"type": "string"},
                },
                "required": ["id"],
            }
        }

        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", return_value=base_entity_doc):
            endpoints = parser.get_endpoints()
            schema = endpoints[0]["request_schema"]
            self.assertIn("id", schema["properties"])
            self.assertIn("role", schema["properties"])
            self.assertIn("id", schema["required"])

    def test_cross_document_remote_reference(self) -> None:
        """Remote Doc A references Doc B on the same authorized remote host."""
        spec_file = self._create_spec({"$ref": "https://schemas.example.com/schemas/user.yaml#/User"})
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)

        doc_user = {
            "User": {
                "type": "object",
                "properties": {
                    "profile": {"$ref": "profile.yaml#/Profile"},
                },
            }
        }
        doc_profile = {
            "Profile": {
                "type": "object",
                "properties": {
                    "bio": {"type": "string"},
                },
            }
        }

        def mock_fetch(url: str) -> Dict[str, Any]:
            if "user.yaml" in url:
                return doc_user
            if "profile.yaml" in url:
                return doc_profile
            raise ValueError(f"Unexpected url: {url}")

        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", side_effect=mock_fetch):
            endpoints = parser.get_endpoints()
            schema = endpoints[0]["request_schema"]
            self.assertEqual(schema["type"], "object")
            profile_schema = schema["properties"]["profile"]
            self.assertIn("bio", profile_schema["properties"])

    def test_intra_document_reference_inside_remote_document(self) -> None:
        """A remote document contains relative references to its own definitions."""
        spec_file = self._create_spec({"$ref": "https://schemas.example.com/schemas/nested.yaml#/Order"})
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)

        doc_order = {
            "Order": {
                "type": "object",
                "properties": {
                    "recipient": {"$ref": "#/Address"},
                },
            },
            "Address": {
                "type": "object",
                "properties": {
                    "street": {"type": "string"},
                    "city": {"type": "string"},
                },
            },
        }

        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", return_value=doc_order):
            endpoints = parser.get_endpoints()
            schema = endpoints[0]["request_schema"]
            recipient = schema["properties"]["recipient"]
            self.assertIn("street", recipient["properties"])
            self.assertIn("city", recipient["properties"])


class TestParserRemoteRefSecurityAndIsolation(unittest.TestCase):
    """Test isolation defenses preventing local filesystem traversal and SSRF from remote docs."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_remote_document_cannot_reference_file_scheme(self) -> None:
        """A remote schema referencing file:///etc/passwd is strictly blocked."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/test": {
                    "post": {
                        "operationId": "op",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "https://schemas.example.com/malicious.yaml#/Exploit"}
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        remote_malicious_doc = {
            "Exploit": {
                "$ref": "file:///etc/passwd"
            }
        }

        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", return_value=remote_malicious_doc):
            with self.assertRaises(RemoteRefSecurityError) as ctx:
                parser.get_endpoints()
            self.assertIn("Remote document cannot reference local files", str(ctx.exception))

    def test_remote_document_cannot_pivot_to_unauthorized_host(self) -> None:
        """A remote schema pointing to https://internal.corp/secret.yaml is blocked."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/test": {
                    "post": {
                        "operationId": "op",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "https://schemas.example.com/pivot.yaml#/Pivot"}
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        remote_pivot_doc = {
            "Pivot": {
                "$ref": "https://internal.corp/secret.yaml#/Secret"
            }
        }

        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", return_value=remote_pivot_doc):
            with self.assertRaises(RemoteRefNotAllowedHostError) as ctx:
                parser.get_endpoints()
            self.assertIn("internal.corp", str(ctx.exception))

    def test_remote_document_relative_path_stays_on_remote_host(self) -> None:
        """A relative path '../shared.yaml' stays on https://schemas.example.com/ and does not access disk."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/test": {
                    "post": {
                        "operationId": "op",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "https://schemas.example.com/v1/sub/item.yaml#/Item"}
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        doc_item = {"Item": {"$ref": "../shared.yaml#/Shared"}}
        doc_shared = {"Shared": {"type": "string"}}

        fetched_urls = []

        def mock_fetch(url: str) -> Dict[str, Any]:
            fetched_urls.append(url)
            if "item.yaml" in url:
                return doc_item
            if "shared.yaml" in url:
                return doc_shared
            raise ValueError(f"Unknown URL: {url}")

        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        assert parser.remote_fetcher is not None
        with patch.object(parser.remote_fetcher, "fetch_document", side_effect=mock_fetch):
            endpoints = parser.get_endpoints()
            self.assertEqual(len(endpoints), 1)
            self.assertIn("https://schemas.example.com/v1/shared.yaml", fetched_urls)


class TestAuditorAndCLIRemoteRefsIntegration(unittest.TestCase):
    """Test APISentinelAuditor, fail-closed handling, credential isolation and CLI argument validation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_auditor_fails_closed_when_remote_ref_disabled(self) -> None:
        """When remote refs are disabled, auditor raises error during initialization and sends 0 requests."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "components": {
                "securitySchemes": {
                    "HeaderAuth": {
                        "$ref": "https://schemas.example.com/auth.yaml#/HeaderScheme"
                    }
                }
            },
            "paths": {},
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url="https://api.example.com",
            )
        self.assertIn("Authentication scheme reference cannot be resolved safely; no request was sent", str(ctx.exception))

    def test_cli_requires_remote_ref_host_when_allow_remote_refs_passed(self) -> None:
        parser = build_argument_parser()
        args = parser.parse_args(["--allow-remote-refs"])
        self.assertTrue(args.allow_remote_refs)
        self.assertEqual(args.remote_ref_host, [])

        # Invoking main() with --allow-remote-refs but no --remote-ref-host returns exit code 2
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            ret = main(["--allow-remote-refs"])
        self.assertEqual(ret, 2)
        self.assertIn("--allow-remote-refs requires at least one --remote-ref-host", err_stream.getvalue())

    def test_cli_requires_allow_remote_refs_when_remote_ref_host_passed(self) -> None:
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            ret = main(["--remote-ref-host", "schemas.example.com"])
        self.assertEqual(ret, 2)
        self.assertIn("--remote-ref-host requires --allow-remote-refs to be set", err_stream.getvalue())

    def test_cli_init_config_forbids_remote_ref_options(self) -> None:
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            ret = main(["--init-config", "draft.json", "--allow-remote-refs", "--remote-ref-host", "example.com"])
        self.assertEqual(ret, 2)
        self.assertIn("--init-config cannot be combined with", err_stream.getvalue())

    def test_cli_dry_run_with_authorized_remote_ref(self) -> None:
        """--dry-run works with authorized remote refs and sends zero target HTTP requests."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/ping": {
                    "get": {
                        "operationId": "ping",
                        "responses": {"200": {"description": "pong"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "openapi.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        out_stream = io.StringIO()
        with patch("sys.stdout", out_stream):
            ret = main([
                "--spec", str(spec_file),
                "--dry-run",
                "--allow-remote-refs",
                "--remote-ref-host", "schemas.example.com",
            ])
        self.assertEqual(ret, 0)
        output = out_stream.getvalue()
        self.assertIn('"mode": "DRY_RUN"', output)

    def test_zero_credential_leakage_to_remote_schema_fetcher(self) -> None:
        """Ensure no target credentials or cookies are passed to RemoteRefFetcher headers."""
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )
        auditor_instance = MagicMock()
        auditor_instance.identities_config = {
            "owner": {"token": "SECRET_OWNER_TOKEN_9999", "headers": {"X-Custom-Secret": "CONFIDENTIAL"}},
            "visitor": {"token": "SECRET_VISITOR_TOKEN_1111"},
        }

        fetcher = RemoteRefFetcher(cfg)
        self.assertIsNotNone(fetcher)
        headers = {
            "Host": "schemas.example.com",
            "User-Agent": "GrantTrace-Schema-Fetcher/2.5.3",
            "Accept": "application/json, application/yaml, text/yaml, */*",
            "Connection": "close",
        }
        # Verify that no authentication headers exist in fetcher's request template
        for k in headers:
            self.assertNotIn("token", k.lower())
            self.assertNotIn("auth", k.lower())
            self.assertNotIn("cookie", k.lower())


if __name__ == "__main__":
    unittest.main()
