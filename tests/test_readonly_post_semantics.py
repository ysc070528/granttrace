"""Compound and body-borne write semantics for declared read-only operations (audit finding F-8).

A read action does not make a compound name read-only: getOrCreateCart,
findOrCreateUser, fetchOrGenerateKey, getOrInitializeSession and findOrInsertRow
write when the resource is missing. A declared read-only POST body can also
ask for a write by itself (a GraphQL mutation, a JSON Patch "op", an upsert
flag, a method override). These tests pin that such operations send nothing,
that genuine read-only names and bodies keep working, that each refusal says
why, and that GET scanning and identity isolation are unchanged.

Every dynamic test talks to a loopback server in this process.
"""

from __future__ import annotations

import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import api_sentinel
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import Verdict
from core.scan_safety import post_path_risk, read_only_body_risk, read_only_risk, read_path_risk


def post(path: str, operation_id: Any = None, summary: Optional[str] = None,
         description: Optional[str] = None) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {"method": "POST", "path": path}
    if operation_id is not None:
        endpoint["operation_id"] = operation_id
    if summary is not None:
        endpoint["summary"] = summary
    if description is not None:
        endpoint["description"] = description
    return endpoint


def signal(endpoint: Dict[str, Any]) -> Optional[str]:
    risk = read_only_risk(endpoint)
    return risk["safety_signal"] if risk else None


class CompoundWriteNamesTests(unittest.TestCase):
    """A. Compound names that write when the resource is missing are refused."""

    REFUSED = {
        "getOrCreateCart": post("/carts/lookup", "getOrCreateCart"),
        "findOrCreateUser": post("/users/search", "findOrCreateUser"),
        "fetchOrGenerateKey": post("/keys/fetch", "fetchOrGenerateKey"),
        "getOrInitializeSession": post("/sessions/get", "getOrInitializeSession"),
        "findOrInsertRow": post("/rows/find", "findOrInsertRow"),
        "getOrInitCache": post("/cache/get", "getOrInitCache"),
        "getOrProvisionTenant": post("/tenants/get", "getOrProvisionTenant"),
        "lookupElseCreateUser": post("/users/lookup", "lookupElseCreateUser"),
        "getUserAndRegisterDevice": post("/users/get", "getUserAndRegisterDevice"),
        # Ambiguous write verbs count directly after the read action.
        "getOrSetCache": post("/cache/get", "getOrSetCache"),
        "getOrPutValue (Kotlin getOrPut)": post("/values/get", "getOrPutValue"),
        "getAndSetFlag (atomic swap)": post("/flags/get", "getAndSetFlag"),
        "findAndClaimJob": post("/jobs/find", "findAndClaimJob"),
        "findOrNewDraft": post("/drafts/find", "findOrNewDraft"),
        "getOrRefreshToken": post("/tokens/get", "getOrRefreshToken"),
        "getOrRotateKey": post("/keys/get", "getOrRotateKey"),
        "searchAndArchive": post("/mail/search", "searchAndArchive"),
        "listAndAcknowledge": post("/alerts/list", "listAndAcknowledge"),
        "getAndMarkRead": post("/messages/get", "getAndMarkRead"),
        # Conditional creation markers.
        "computeIfAbsent": post("/cache/compute", "computeIfAbsent"),
        "getIfAbsentPut": post("/values/get", "getIfAbsentPut"),
        "getCartCreateIfMissing": post("/carts/get", "getCartCreateIfMissing"),
        "fetchTokenIfNotExists": post("/tokens/fetch", "fetchTokenIfNotExists"),
        # Leading writes and abbreviations a declared read-only POST cannot use.
        "ensureCart": post("/carts/lookup", "ensureCart"),
        "initializeSession": post("/sessions/lookup", "initializeSession"),
        "delUser": post("/users/search", "delUser"),
        "updProfile": post("/profiles/search", "updProfile"),
    }

    def test_compound_write_names_are_refused_with_an_explanation(self):
        for name, endpoint in self.REFUSED.items():
            with self.subTest(name=name):
                risk = read_only_risk(endpoint)
                self.assertIsNotNone(risk)
                self.assertEqual(risk["safety_signal"], "operation_id")
                self.assertTrue(risk["safety_reason"].endswith("no request was sent"))

    def test_the_reason_names_the_compound_without_echoing_metadata(self):
        risk = read_only_risk(post("/carts/lookup", "getOrCreateCart"))
        self.assertIn("get-or-create", risk["safety_reason"])
        self.assertNotIn("getOrCreateCart", risk["safety_reason"])
        self.assertNotIn("Cart", risk["safety_reason"])

    def test_compound_names_are_refused_for_get_too(self):
        # A GET named getOrCreate writes as well; the default read path refuses it.
        for operation_id in ("getOrCreateCart", "findOrInsertRow", "getAndSetFlag", "computeIfAbsent"):
            with self.subTest(operation_id=operation_id):
                self.assertEqual(signal({"method": "GET", "path": "/x/{id}", "operation_id": operation_id}),
                                 "operation_id")
        self.assertIsNone(signal({"method": "GET", "path": "/x/{id}", "operation_id": "getOrDefault"}))


class NamingVariantTests(unittest.TestCase):
    """C. Case and separator variants, in the operationId and in the path."""

    def test_spellings_of_get_or_create_are_all_refused(self):
        for operation_id in ("get_or_create_cart", "GET_OR_CREATE_CART", "get-or-create-cart", "GetOrCreateCart",
                             "getORCreateCart", "get.or.create", "Get Or Create Cart", "getOr\u200bCreateCart"):
            with self.subTest(operation_id=operation_id):
                self.assertEqual(signal(post("/carts/search", operation_id)), "operation_id")

    def test_generator_naming_conventions_are_recognised(self):
        # Azure (Resource_Operation), Google (resource.method), NestJS (Controller_method),
        # FastAPI (name_path_method) operationIds carry a resource prefix or suffix.
        for operation_id in ("Carts_GetOrCreate", "Orders_GetOrSet", "orders.getOrSet", "OrdersController_getOrPut",
                             "Inventory_FindAndLock", "get_or_create_cart_api_v1_carts_lookup_post"):
            with self.subTest(operation_id=operation_id):
                self.assertEqual(signal(post("/x/search", operation_id)), "operation_id")
        for operation_id in ("Cards_GetCardOrSet", "Users_GetByEmailOrLogin", "Orders_Search",
                             "search_orders_api_v1_orders_search_post", "OrdersController_findAll"):
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(read_only_risk(post("/x/search", operation_id)))

    def test_path_segments_are_refused_in_every_spelling(self):
        for path in ("/carts/get-or-create", "/carts/getOrCreate", "/carts/find_or_create", "/values/put-if-absent"):
            with self.subTest(path=path):
                self.assertEqual(signal(post(path, "searchCarts")), "path")

    def test_concrete_path_values_are_checked_at_request_time(self):
        self.assertIsNotNone(post_path_risk("/carts/get-or-create/lookup"))
        self.assertIsNotNone(post_path_risk("/carts/getOrCreate/lookup"))
        self.assertIsNotNone(post_path_risk("/carts/find%5For%5Fcreate/lookup"))
        # Identifiers are data: an id that starts with an abbreviation is not a command.
        self.assertIsNone(post_path_risk("/rooms/rm-101/lookup"))
        self.assertIsNone(post_path_risk("/documents/doc-1001/lookup"))


class MissingOrUnusualOperationIdTests(unittest.TestCase):
    """D. A missing or unusual operationId falls back to the path; look-alike text is not trusted."""

    def test_missing_or_non_string_operation_ids_use_the_path(self):
        for operation_id in (None, 123, ["x"], {"a": 1}, ""):
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(read_only_risk(post("/carts/search", operation_id)))
                self.assertEqual(signal(post("/carts/get-or-create", operation_id)), "path")

    def test_full_width_spelling_is_normalised_before_the_check(self):
        full_width = "".join(chr(ord(char) + 0xFEE0) for char in "getOrCreateCart")
        self.assertEqual(signal(post("/carts/search", full_width)), "operation_id")

    def test_ascii_words_with_look_alike_letters_are_refused(self):
        # A Cyrillic "\u0435" in "Create" would drop the action word from the ASCII word split.
        risk = read_only_risk(post("/carts/search", "getOrCr\u0435ateCart"))
        self.assertEqual(risk["safety_signal"], "identifier_script")
        self.assertIn("non-ASCII", risk["safety_reason"])
        self.assertEqual(signal(post("/carts/s\u0435arch")), "identifier_script")
        # Words written wholly in another script are not look-alikes.
        self.assertIsNone(read_only_risk(post("/orders/search", "searchOrders", "查询订单")))


class ContradictoryMetadataTests(unittest.TestCase):
    """E. A benign path cannot rescue a writing operationId, nor the reverse."""

    def test_either_side_naming_a_write_refuses_the_operation(self):
        cases = {
            ("/carts/search", "getOrCreateCart"): "operation_id",
            ("/carts/get-or-create", "searchCarts"): "path",
            ("/carts/search", "createCart"): "operation_id",
            ("/carts/create", "searchCarts"): "path",
            ("/carts/{id}/delete", "searchCarts"): "path",
        }
        for (path, operation_id), expected in cases.items():
            with self.subTest(path=path, operation_id=operation_id):
                self.assertEqual(signal(post(path, operation_id)), expected)


class MisleadingDescriptionTests(unittest.TestCase):
    """G. Prose that reveals a conditional write refuses an innocently named operation."""

    def test_prose_alternatives_that_write_are_refused(self):
        cases = {
            ("Get or create a cart", None): "summary",
            ("Fetch or generate an API key", None): "summary",
            ("Get or initialize session state", None): "summary",
            ("Look up or create an account", None): "summary",
            ("Look up a cart", "Returns the cart, or creates one if none exists."): "description",
            ("Find a user", "Finds the user or inserts a new row."): "description",
            ("Look up a cart", "Creates the cart if missing."): "description",
        }
        for (summary, description), expected in cases.items():
            with self.subTest(summary=summary, description=description):
                self.assertEqual(signal(post("/carts/lookup", "lookupCart", summary, description)), expected)

    def test_alternatives_between_nouns_are_not_refused(self):
        for summary in ("Search users by email or login name", "Search by name or address.",
                        "Find orders by date or schedule", "Search or filter orders",
                        "Search transactions by status or refund state",
                        "Returns 404 if the order does not exist or the caller cannot view it.",
                        "Lists reviewers who can approve or reject the request.",
                        "Returns the cached value or computes it"):
            with self.subTest(summary=summary):
                self.assertIsNone(read_only_risk(post("/records/search", "searchRecords", summary, summary)))


class GenuineReadOnlyNamesTests(unittest.TestCase):
    """B and H. Read-only names, including ones containing "or", keep working."""

    def test_read_only_post_names_are_still_allowed(self):
        for path, operation_id in (
                ("/products/search", "searchProducts"), ("/orders/query", "queryOrders"),
                ("/results/filter", "filterResults"), ("/orders/search", "searchOrders"),
                ("/orgs/query", "queryOrgs"), ("/orders/list", "listOrders"), ("/users/lookup", "lookupUser"),
                ("/orders/get", "getOrderById"), ("/orders/find", "findOrdersByStatus"),
                ("/settings/get", "getOrDefault"), ("/users/find", "findOrFail"), ("/users/get", "getOrNull"),
                ("/users/get", "getOrElseEmpty"), ("/users/search", "searchByNameOrEmail"),
                ("/billing/search", "searchOrdersOrInvoices"), ("/users/lookup", "lookupOrCount"),
                ("/orders/search", "searchOrderUpdates"), ("/reports/query", "queryReportsOrderedByDate"),
                ("/parties/get", "getVendorOrCustomer"), ("/users/get", "getUserIfExists"),
                ("/settings/get", "getDefaultIfMissing"), ("/values/get", "getIfAbsent"),
                ("/cards/get", "getCardOrSet"), ("/products/get", "getProductOrStore"),
                ("/cars/search", "getUsedOrNew"), ("/users/find", "findUserByEmailOrLogin"),
                ("/payments/get", "getPaymentOrRefund"), ("/reports/search", "searchHTMLReports"),
                ("/tokens/get", "getAccessOrRefreshToken"), ("/jobs/search", "listImportsAndExports"),
                ("/jobs/get", "getImportOrExportStatus"), ("/docs/get", "getMarkdownOrHtml"),
                ("/tokens/get", "getRefreshTokenInfo")):
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(read_only_risk(post(path, operation_id)))

    def test_previously_supported_read_only_posts_are_unchanged(self):
        for endpoint in ({"method": "POST", "path": "/orders/search"}, {"method": "POST", "path": "/v1/_search"},
                         {"method": "POST", "path": "/rpc", "operation_id": "getUser"},
                         {"method": "POST", "path": "/reports/query"}, {"method": "POST", "path": "/archives/lookup"},
                         {"method": "POST", "path": "/api/documents/search", "summary": "Search documents"}):
            with self.subTest(endpoint=endpoint):
                self.assertIsNone(read_only_risk(endpoint))

    def test_get_read_names_with_conjunctions_are_unchanged(self):
        for operation_id in ("getUsersAndGroups", "listOrdersAndInvoices", "getOldAndNewValues", "getSettingsOrDefaults",
                             "getPrimaryOrSecondary", "getCachedOrFresh", "listOpenOrClosed", "getUploadOrDownloadUrl",
                             "getEventOrSchedule", "getPolicyOrClaim", "getMakeAndModel", "getNewArrivals",
                             "connectGetNamespacedPodExec", "GetCheckoutSessions", "GetTransfers"):
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(read_only_risk({"method": "GET", "path": "/x", "operation_id": operation_id}))
        for path in ("/terms-and-conditions", "/questions-and-answers", "/make-and-model", "/used-or-new/cars",
                     "/sets/{id}", "/stores/{id}/inventory", "/locks/status", "/claims/{id}"):
            with self.subTest(path=path):
                self.assertIsNone(read_only_risk({"method": "GET", "path": path}))


class RequestBodyTests(unittest.TestCase):
    """F. Empty and complex bodies are allowed; a body that asks for a write is not."""

    WRITES = {
        "GraphQL mutation": {"query": "mutation { deleteUser(id: \"1002\") { id } }"},
        "named GraphQL mutation with variables": {"query": "mutation Remove($id: ID!) {\n remove(id: $id) { id } }",
                                                  "variables": {"id": "1"}},
        "GraphQL document string": "mutation{createCart{id}}",
        "persisted GraphQL operation name": {"operationName": "CreateUser", "extensions": {"persistedQuery": {}}},
        "JSON Patch op": [{"op": "replace", "path": "/role", "value": "admin"}],
        "action selector": {"action": "create", "cart": {"id": "c-1"}},
        "nested command": {"request": {"command": "deleteAll"}},
        "method override": {"_method": "DELETE", "id": "o-1"},
        "method override header field": {"X-HTTP-Method-Override": "patch"},
        "upsert flag": {"filter": {"title": "x"}, "upsert": True},
        "create-if-missing flag": {"createIfMissing": True},
        "auto create flag": {"auto_create": "true"},
        "save search flag": {"q": "x", "save_search": 1},
        "store results flag": {"store": True},
        "dry run disabled": {"dryRun": False},
        "validate only disabled": {"validate_only": "false"},
    }
    READS = {
        "empty object": {},
        "empty array": [],
        "empty string": "",
        "number selector": 0,
        "nested filter": {"filter": {"owner_id": "1001", "deleted": True, "status": ["open", "closed"]},
                          "sort": [{"field": "updated_at", "order": "desc"}], "page": {"size": 10, "cursor": None}},
        "GraphQL query": {"query": "query { user(id: \"1001\") { name mutationCount } }"},
        "full-text search for the word mutation": {"query": "mutation testing"},
        "filter operators": {"where": [{"field": "status", "op": "eq", "value": "open"}, {"op": "in", "value": [1]}]},
        "disabled write flags": {"upsert": False, "save": "false", "create": 0},
        "dry run kept on": {"dry_run": True},
        "read options": {"include_deleted": True, "follow_redirects": True, "method": "card", "action": "view"},
    }

    # Fixed texts only: no key or value of the body is ever part of a reason.
    REASONS = {"Read-only POST body contains " + kind + "; no request was sent" for kind in (
        "a GraphQL mutation", "an action that names a write", "an HTTP method override to PUT, PATCH or DELETE",
        "a dry-run switch turned off", "a flag that asks for a write")}

    def test_bodies_that_ask_for_a_write_are_refused_without_echoing_them(self):
        for name, body in self.WRITES.items():
            with self.subTest(name=name):
                risk = read_only_body_risk(body)
                self.assertIsNotNone(risk)
                self.assertEqual(risk["safety_signal"], "request_body")
                self.assertIn(risk["safety_reason"], self.REASONS)

    def test_empty_and_complex_read_bodies_are_allowed(self):
        for name, body in self.READS.items():
            with self.subTest(name=name):
                self.assertIsNone(read_only_body_risk(body))

    def test_configuration_validation_refuses_a_writing_body(self):
        for key, policy in (
                ("body", {"read_only": True, "body": {"query": "mutation { a { id } }"}}),
                ("identity_bodies.owner", {"read_only": True, "identity_bodies": {"owner": {"upsert": True}}}),
                ("identity_bodies.visitor_self", {"read_only": True, "identity_bodies": {
                    "owner": {"id": "a"}, "visitor_self": {"id": "b", "_method": "PUT"}}})):
            with self.subTest(key=key):
                result = ConfigValidator.validate({"bola": {"POST /graph/query": policy}})
                self.assertFalse(result.is_valid)
                issue = next(item for item in result.errors if item.path == f"bola.POST /graph/query.{key}")
                self.assertIn("never audited as read-only", issue.message)
                self.assertEqual(issue.actual, "state-changing request body (value not shown)")

    def test_long_bodies_and_identifiers_are_checked_in_linear_time(self):
        # A regular expression with adjacent whitespace quantifiers backtracks
        # quadratically on a 64 KiB body of spaces; these complete in milliseconds.
        started = time.monotonic()
        self.assertIsNone(read_only_body_risk({"query": "mutation" + " " * 65000 + "x"}))
        self.assertIsNone(read_only_body_risk({"query": "mutation" + " " * 30000 + "Name" + " " * 30000 + "("}))
        self.assertIsNone(read_only_risk(post("/x/search", "A" * 65000)))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_role_bodies_used_by_rbac_probes_are_checked_too(self):
        identities = {"owner": {"id": "1", "token": "Bearer OWNER_TOKEN_F8"},
                      "visitor": {"id": "2", "token": "Bearer VISITOR_TOKEN_F8"}, "anonymous": {},
                      "roles": {"admin": {"token": "Bearer ADMIN_TOKEN_F8", "role": "administrator",
                                          "body": {"query": "mutation { resetAll { ok } }"}},
                                "viewer": {"token": "Bearer VIEWER_TOKEN_F8", "body": {"q": "reports"}}}}
        result = ConfigValidator.validate({"identities": identities})
        self.assertEqual([issue.path for issue in result.errors], ["identities.roles.admin.body"])
        self.assertIn("GraphQL mutation", result.errors[0].message)
        self.assertNotIn("resetAll", result.errors[0].message + str(result.errors[0].actual))

    def test_identity_and_role_headers_cannot_override_the_method(self):
        # Identity headers ride on every request: an override would turn each GET into a write.
        identities = {"owner": {"id": "1", "token": "Bearer OWNER_TOKEN_F8",
                                "headers": {"X-HTTP-Method-Override": "DELETE"}},
                      "visitor": {"id": "2", "token": "Bearer VISITOR_TOKEN_F8",
                                  "headers": {"X-HTTP-Method-Override": "GET", "X-Tenant": "t-1"}},
                      "anonymous": {},  # Anonymous headers are refused outright by an existing rule.
                      "roles": {"admin": {"token": "Bearer ADMIN_TOKEN_F8", "headers": {"x-method-override": "PATCH"}},
                                "viewer": {"token": "Bearer VIEWER_TOKEN_F8", "headers": {"X-HTTP-Method": "post"}}}}
        result = ConfigValidator.validate({"identities": identities})
        self.assertEqual(sorted(issue.path for issue in result.errors), [
            "identities.owner.headers.X-HTTP-Method-Override", "identities.roles.admin.headers.x-method-override",
            "identities.roles.viewer.headers.X-HTTP-Method"])
        for issue in result.errors:
            self.assertTrue(str(issue.actual).endswith("[VALUE REDACTED]"))

    def test_the_body_check_applies_only_to_a_declared_read_only_post(self):
        # Without read_only nothing is sent; the existing warning still applies.
        result = ConfigValidator.validate({"bola": {"POST /graph/query": {"body": {"upsert": True}}}})
        self.assertTrue(result.is_valid)
        self.assertTrue(any(issue.path == "bola.POST /graph/query.read_only" for issue in result.warnings))

    def test_configuration_validation_accepts_read_bodies(self):
        result = ConfigValidator.validate({"bola": {"POST /api/documents/search": {
            "read_only": True, "identity_bodies": {"owner": {"doc_id": "doc_owner_1001"},
                                                   "visitor_self": {"doc_id": "doc_visitor_2002"}}}}})
        self.assertTrue(result.is_valid, [issue.message for issue in result.errors])


class _RecordingApi(BaseHTTPRequestHandler):
    """Loopback API: records every request, answers by bearer token."""

    requests: List[Tuple[str, str, Optional[str], str]] = []
    lock = threading.Lock()

    def log_message(self, *args: Any) -> None:
        pass

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        auth = self.headers.get("Authorization")
        with self.lock:
            type(self).requests.append((self.command, self.path.split("?")[0], auth, body))
        if not auth:
            status, document = 401, {"error": "Unauthorized"}
        else:
            account = "1001" if "OWNER" in auth else "1002"
            status, document = 200, {"id": account, "note": "record of " + account}
        data = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _answer


def _operation(operation_id: str, summary: Optional[str] = None, description: Optional[str] = None,
               parameters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"operationId": operation_id, "responses": {"200": {"description": "OK"}}}
    if summary:
        operation["summary"] = summary
    if description:
        operation["description"] = description
    if parameters:
        operation["parameters"] = parameters
    return operation


ID = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]
SELECTORS = {"identity_bodies": {"owner": {"id": "1001"}, "visitor_self": {"id": "1002"}}}
DANGEROUS = {
    "/carts/lookup": (_operation("getOrCreateCart"), {"body": {"cart": "c-1"}}),
    "/users/search": (_operation("findOrCreateUser"), {"body": {"email": "owner@example.test"}}),
    "/keys/fetch": (_operation("fetchOrGenerateKey"), {"body": {"key": "k-1"}}),
    "/sessions/get": (_operation("getOrInitializeSession"), {"body": {"sid": "s-1"}}),
    "/rows/find": (_operation("findOrInsertRow"), {"body": {"row": 1}}),
    "/carts/get-or-create": (_operation("searchCarts"), {"body": {"cart": "c-1"}}),
    "/accounts/lookup": (_operation("lookupAccount", "Look up an account",
                                    "Returns the account, or creates one if none exists."), {"body": {"acct": "a"}}),
    "/graphql": (_operation("queryGraph", "Query the API"),
                 {"body": {"query": "mutation { deleteUser(id: \"1002\") { id } }"}}),
    "/documents/find": (_operation("findDocuments", "Find documents"), {"body": {"title": "x", "upsert": True}}),
    "/revisions/lookup": (_operation("lookupRevision"), {"body": [{"op": "replace", "path": "/role", "value": "x"}]}),
    "/orders/query": (_operation("queryOrders", "Query orders"), {"body": {"_method": "DELETE", "order": "o-1"}}),
}
GENUINE = {
    "/products/search": _operation("searchProducts", "Search products"),
    "/orders/lookup": _operation("lookupOrder", "Look up an order",
                                 "Returns the order, or 404 if the caller cannot view it."),
    "/settings/get": _operation("getOrDefault"),
    "/articles/search": _operation("searchArticles", "Search articles by title or author"),
}
GENUINE_BODIES = {
    "/articles/search": {"identity_bodies": {"owner": {"query": "mutation testing", "author": "1001"},
                                             "visitor_self": {"query": "mutation testing", "author": "1002"}}},
}


class LoopbackScanTests(unittest.TestCase):
    """End to end through the real transport: what reaches the server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingApi)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_address[1]}"
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.folder = Path(folder.name)
        paths: Dict[str, Any] = {path: {"post": operation} for path, (operation, _) in DANGEROUS.items()}
        paths.update({path: {"post": operation} for path, operation in GENUINE.items()})
        paths["/users/{id}"] = {"get": _operation("getUser", parameters=ID)}
        cls.spec = {"openapi": "3.0.3", "info": {"title": "F-8", "version": "1"}, "paths": paths,
                    "security": [{"bearer": []}],
                    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}}
        cls.spec_path = cls.folder / "spec.json"
        cls.spec_path.write_text(json.dumps(cls.spec), encoding="utf-8")
        cls.identities = {"owner": {"id": "1001", "token": "Bearer OWNER_TOKEN_F8"},
                          "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN_F8"}, "anonymous": {}}
        cls.bola = {f"POST {path}": dict(read_only=True, **policy) for path, (_, policy) in DANGEROUS.items()}
        cls.bola.update({f"POST {path}": dict(read_only=True, **GENUINE_BODIES.get(path, SELECTORS))
                         for path in GENUINE})

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        with _RecordingApi.lock:
            _RecordingApi.requests = []

    def scan(self) -> APISentinelAuditor:
        auditor = APISentinelAuditor(str(self.spec_path), self.target, request_delay=0, max_workers=3,
                                     identities_config=self.identities, bola_config=self.bola)
        with redirect_stdout(io.StringIO()):
            auditor.run()
        return auditor

    def sent(self, method: str, path: str) -> List[Tuple[str, str, Optional[str], str]]:
        return [item for item in _RecordingApi.requests if item[0] == method and item[1] == path]

    def test_dangerous_posts_are_never_sent_and_say_why(self):
        auditor = self.scan()
        results = {item["endpoint"]: item for item in auditor.results}
        for path in DANGEROUS:
            with self.subTest(path=path):
                self.assertEqual(self.sent("POST", path), [])
                result = results[f"POST {path}"]
                self.assertIn(result["verdict"], (Verdict.SKIPPED.value, Verdict.INCONCLUSIVE.value))
                self.assertEqual(result["evidence"]["requests_attempted"], 0)
                self.assertIn("no request was sent", result["reason"])
        for path in ("/carts/lookup", "/users/search", "/keys/fetch", "/sessions/get", "/rows/find"):
            self.assertIn("conditional or follow-up write", results[f"POST {path}"]["reason"])
        self.assertEqual(results["POST /carts/get-or-create"]["evidence"]["safety_signal"], "path")
        self.assertEqual(results["POST /accounts/lookup"]["evidence"]["safety_signal"], "description")

    def test_genuine_read_only_posts_are_still_sent_with_their_bodies(self):
        self.scan()
        for path in GENUINE:
            with self.subTest(path=path):
                requests = self.sent("POST", path)
                # Owner, Visitor cross, Anonymous, Visitor self.
                self.assertEqual(len(requests), 4)
                owner_body = json.loads(requests[0][3]) if requests[0][2] == "Bearer OWNER_TOKEN_F8" else None
                self.assertIsNotNone(owner_body)

    def test_get_scanning_and_identity_isolation_are_unchanged(self):
        self.scan()
        gets = self.sent("GET", "/users/1001") + self.sent("GET", "/users/1002")
        self.assertEqual(sorted((path, auth or "") for _, path, auth, _ in gets), sorted([
            ("/users/1001", "Bearer OWNER_TOKEN_F8"), ("/users/1001", "Bearer VISITOR_TOKEN_F8"),
            ("/users/1001", ""), ("/users/1002", "Bearer VISITOR_TOKEN_F8")]))
        self.assertEqual([item for item in _RecordingApi.requests if item[0] not in ("GET", "POST")], [])

    def test_cli_validation_explains_a_writing_body_and_sends_nothing(self):
        config = self.folder / "config.json"
        config.write_text(json.dumps({"identities": self.identities, "bola": {
            "POST /graphql": {"read_only": True, "body": {"query": "mutation { deleteUser(id: \"1\") { id } }"}}}}),
            encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = api_sentinel.main(["--spec", str(self.spec_path), "--config", str(config), "--target", self.target,
                                      "--output", str(self.folder / "report.html")])
        self.assertEqual(code, 2)
        self.assertIn("GraphQL mutation", stdout.getvalue() + stderr.getvalue())
        self.assertNotIn("deleteUser", stdout.getvalue() + stderr.getvalue())
        self.assertEqual(_RecordingApi.requests, [])

    def test_dry_run_plan_marks_compound_posts_as_blocked(self):
        config = self.folder / "plan-config.json"
        config.write_text(json.dumps({"identities": self.identities, "bola": {
            "POST /carts/lookup": {"read_only": True, "body": {"cart": "c-1"}},
            "POST /products/search": dict(read_only=True, **SELECTORS)}}), encoding="utf-8")
        plan_path = self.folder / "plan.json"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = api_sentinel.main(["--spec", str(self.spec_path), "--config", str(config), "--dry-run",
                                      "--export-json", str(plan_path)])
        self.assertEqual(code, 0)
        plan = {entry["endpoint"]: entry for entry in json.loads(plan_path.read_text(encoding="utf-8"))["operations"]}
        self.assertTrue(plan["POST /carts/lookup"]["safety_blocked"])
        self.assertEqual(plan["POST /carts/lookup"]["safety_signal"], "operation_id")
        self.assertNotIn("safety_blocked", plan["POST /products/search"])
        self.assertEqual(_RecordingApi.requests, [])


class ExportIsAReadTests(unittest.TestCase):
    """Round 2: "export" was treated as a write and refused ordinary report downloads.

    On ad125aa these GET and POST operations were scanned; 05a649d refused them.
    """

    def test_export_and_view_alternatives_are_reads(self):
        for method, path, summary in (
                ("GET", "/reports/{id}", "View or export a report"),
                ("GET", "/invoices/{id}", "Preview or export the invoice PDF"),
                ("GET", "/audit", "List or export audit events"),
                ("GET", "/reports/{id}", "Returns the report as JSON or exports the CSV file"),
                ("GET", "/messages/{id}", "View or mark the read state"),
                ("POST", "/reports/search", "Search or export reports")):
            with self.subTest(method=method, summary=summary):
                self.assertIsNone(read_only_risk({"method": method, "path": path, "summary": summary,
                                                  "description": summary}))
        for operation_id in ("viewOrExportReport", "getAndExportCsv", "searchAndExport"):
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(read_only_risk({"method": "GET", "path": "/reports", "operation_id": operation_id}))


class RoundTwoIdentifierTests(unittest.TestCase):
    """Round 2: compounds with a modifier or an unambiguous queue verb, and invisible characters."""

    def test_queue_verbs_and_modifiers_are_refused(self):
        for operation_id in ("getNextAndDequeue", "fetchMessagesAndAck", "listJobsAndAcknowledge", "pollAndConsume",
                             "getOrAutoCreate", "findOrLazyInit", "getOrMaybeCreate", "findOrForceInsert",
                             "compareAndSet", "compareAndSwap", "getOrOverwrite"):
            with self.subTest(operation_id=operation_id):
                self.assertEqual(signal(post("/x/search", operation_id)), "operation_id")
                self.assertEqual(signal({"method": "GET", "path": "/x", "operation_id": operation_id}), "operation_id")

    def test_invisible_and_combining_characters_cannot_hide_the_action_word(self):
        for operation_id in ("getOrCre\u200bateCart", "getOrCre\xadateCart", "getOrCre\u2060ateCart",
                             "getOrCre\ufeffateCart", "getOrCre\u0332ateCart"):
            with self.subTest(operation_id=ascii(operation_id)):
                self.assertEqual(signal(post("/carts/search", operation_id)), "operation_id")
                self.assertEqual(signal({"method": "GET", "path": "/x", "operation_id": operation_id}), "operation_id")

    def test_nouns_next_to_queue_verbs_are_not_refused(self):
        for operation_id in ("getAckOrNack", "listAcksAndNacks", "getConsumerGroups", "compareVersions",
                             "getConsumerOrProducer", "listAcquisitions"):
            with self.subTest(operation_id=operation_id):
                self.assertIsNone(read_only_risk(post("/x/search", operation_id)))


class RoundTwoGraphQLTests(unittest.TestCase):
    """Round 2: GraphQL ignores commas, comments and a byte order mark; variables may nest parentheses."""

    def test_mutations_with_ignored_tokens_or_nested_arguments_are_refused(self):
        for document in ("mutation, { a }", "mutation # comment\n{ a }", "mutation\ufeff{ a }",
                         "mutation M,($id: ID!,) , { a(id: $id) }",
                         "mutation M($id: ID! @deprecated(reason: \"x\")) { a(id: $id) }",
                         "mutation M($s: String = \"a)b\") { a(s: $s) }",
                         "# header\nmutation\n# between\n{ a }",
                         "query Q { x }\nmutation M @live { y }"):
            with self.subTest(document=document):
                self.assertIsNotNone(read_only_body_risk({"query": document}))

    def test_text_that_mentions_mutation_is_not_refused(self):
        for text in ("mutation testing", "mutation (genetics)", "query { mutationCount }", "Mutation { a }",
                     "{ a(text: \"mutations\") }", "#mutation\nquery { a }"):
            with self.subTest(text=text):
                self.assertIsNone(read_only_body_risk({"query": text}))

    def test_pathological_documents_are_checked_quickly(self):
        started = time.monotonic()
        for document in ("mutation" + "#" * 65000, ("mutation(" * 7000), "mutation " + "," * 65000 + "x",
                         "mutation M(" + "(" * 30000, "{" + "mutation#" * 7000, "{" + "mutation " * 7000,
                         "{\"" + "\\\"" * 30000, "{" + "\"\"\"" * 20000, "{ " + "mutation" + " ," * 30000 + "x"):
            read_only_body_risk({"query": document})
        self.assertLess(time.monotonic() - started, 2.0)


class RoundTwoBodyTests(unittest.TestCase):
    """Round 2: nested JSON text, write modes and namespaced actions; data fields named after verbs."""

    def test_more_writing_bodies_are_refused(self):
        for body in ({"request": "{\"action\": \"delete\"}"}, {"payload": "[{\"op\": \"remove\", \"path\": \"/a\"}]"},
                     {"upsert": 1.0}, {"mode": "upsert"}, {"write_mode": "overwrite"}, {"actions": ["create"]},
                     {"operations": [{"op": "add"}]}, {"action": "cart.create"}, {"op": "users:delete"},
                     {"operationType": "mutation"}):
            with self.subTest(body=body):
                self.assertIsNotNone(read_only_body_risk(body))

    def test_data_fields_named_after_verbs_are_not_write_flags(self):
        # Audit columns and soft-delete markers are common filters, as are ids under noun-like keys.
        for body in ({"filter": {"create_by": 1}}, {"create_time": "2026-01-01"}, {"delete_flag": 1},
                     {"del_flag": 0}, {"is_delete": 0}, {"update_user": 1}, {"store": 1}, {"store_id": 7},
                     {"register": 2}, {"mode": "insensitive"}, {"filter": "{\"status\": \"open\"}"},
                     {"action": "view_details"}, {"commit": "4f2a9c1"},
                     {"where": [{"field": "name", "op": "startsWith", "value": "a"}]}, {"op": "starts_with"}):
            with self.subTest(body=body):
                self.assertIsNone(read_only_body_risk(body))
        self.assertIsNotNone(read_only_body_risk({"store": True}))


class QueryStringWriteTests(unittest.TestCase):
    """Round 2 (boundary B): a query string can ask for a write; every request URL is checked."""

    def test_query_write_switches_are_refused_at_request_time(self):
        for url in ("http://127.0.0.1/carts/lookup?upsert=true", "http://127.0.0.1/carts/lookup?create=1",
                    "http://127.0.0.1/x/search?_method=DELETE", "http://127.0.0.1/items/1?commit=true",
                    "http://127.0.0.1/x/search?dry_run=false", "http://127.0.0.1/x/search?action=delete",
                    "http://127.0.0.1/graphql?query=mutation%7Ba%7D", "http://127.0.0.1/x?createIfMissing=yes",
                    "http://127.0.0.1/x?page=2&auto_create=true"):
            with self.subTest(url=url):
                risk = read_path_risk(url)
                self.assertIsNotNone(risk)
                self.assertEqual(risk["safety_signal"], "query")
                self.assertNotIn("upsert", risk["safety_reason"])

    def test_ordinary_query_data_is_not_refused(self):
        for url in ("http://127.0.0.1/records/1001?redirect=%252fopaque%252fcreate_report&data=..%2f",
                    "http://127.0.0.1/x?page=1&size=10", "http://127.0.0.1/x?include_deleted=true",
                    "http://127.0.0.1/x?store=1", "http://127.0.0.1/x?create_time=2026-01-01",
                    "http://127.0.0.1/x?q=mutation%20testing", "http://127.0.0.1/x?sort=updated_at&action=view",
                    "http://127.0.0.1/x?delete_flag=1", "http://127.0.0.1/x?field=name&op=startsWith&value=a"):
            with self.subTest(url=url):
                self.assertIsNone(read_path_risk(url))


class PassiveWriteDescriptionTests(unittest.TestCase):
    """Round 2 (boundary C): a description that creates the resource when it is missing."""

    def test_existence_conditional_writes_are_refused(self):
        for description in ("If the cart does not exist, a new one is created.", "A cart is created if none exists.",
                            "If no session exists, one is initialized automatically.",
                            "If it does not exist, the server creates it.",
                            "When the profile doesn't exist yet it will be generated."):
            with self.subTest(description=description):
                self.assertEqual(signal(post("/carts/lookup", "lookupCart", "Look up a cart", description)),
                                 "description")
                self.assertEqual(signal({"method": "GET", "path": "/carts/{id}", "operation_id": "getCart",
                                         "description": description}), "description")

    def test_descriptions_of_missing_or_created_data_are_not_refused(self):
        for description in ("Returns 404 if the order does not exist or was created by another user.",
                            "Returns orders that are created by the caller.", "If no issues exist, an empty list is returned.",
                            "Returns 404 if the item is not found.", "Lists stores; stores that do not exist are skipped."):
            with self.subTest(description=description):
                self.assertIsNone(read_only_risk(post("/orders/search", "searchOrders", "Search orders", description)))


class QueryStringLoopbackTests(unittest.TestCase):
    """End to end: a query default that asks for a write sends nothing, for GET and for read-only POST."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingApi)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.target = f"http://127.0.0.1:{cls.server.server_address[1]}"
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        flag = {"name": "upsert", "in": "query", "schema": {"type": "boolean", "default": True}}
        create = {"name": "create", "in": "query", "required": True, "schema": {"type": "boolean", "enum": [True]}}
        spec = {"openapi": "3.0.3", "info": {"title": "F-8 query", "version": "1"}, "security": [{"bearer": []}],
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "paths": {"/carts/lookup": {"post": _operation("lookupCart", parameters=[flag])},
                          "/folders/{id}": {"get": _operation("getFolder", parameters=ID + [create])},
                          "/users/{id}": {"get": _operation("getUser", parameters=ID)}}}
        cls.spec_path = Path(folder.name) / "spec.json"
        cls.spec_path.write_text(json.dumps(spec), encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_query_write_switches_send_nothing(self):
        with _RecordingApi.lock:
            _RecordingApi.requests = []
        identities = {"owner": {"id": "1001", "token": "Bearer OWNER_TOKEN_F8"},
                      "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN_F8"}, "anonymous": {}}
        auditor = APISentinelAuditor(str(self.spec_path), self.target, request_delay=0, identities_config=identities,
                                     bola_config={"POST /carts/lookup": {"read_only": True,
                                                                         "body": {"cart": "c-1"}}})
        with redirect_stdout(io.StringIO()):
            auditor.run()
        sent = {(method, path) for method, path, _, _ in _RecordingApi.requests}
        self.assertNotIn(("POST", "/carts/lookup"), sent)
        self.assertFalse(any(path.startswith("/folders/") for _, path in sent))
        self.assertIn(("GET", "/users/1001"), sent)
        results = {item["endpoint"]: item for item in auditor.results}
        for key in ("POST /carts/lookup", "GET /folders/{id}"):
            self.assertEqual(results[key]["evidence"]["safety_signal"], "query")
            self.assertEqual(results[key]["evidence"]["requests_attempted"], 0)


if __name__ == "__main__":
    unittest.main()
