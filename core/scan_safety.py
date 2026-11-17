"""Conservative local checks for read-path ambiguity and mutation semantics.

These rules cannot prove that an operation is side-effect free. They identify
command-like paths/operation identifiers and affirmative mutation descriptions;
an undocumented server-side effect still requires operator review.

POST is not read-only by HTTP semantics. A POST is considered only after the
operator declares ``read_only: true``; the declaration is then checked against
a wider mutation vocabulary and must be corroborated by an explicit read action
(search, query, lookup...) in the path, operationId or summary. A heuristic
match never proves a POST is safe; it only refuses ones that are not plausibly
read-only.

A read action does not make a compound name read-only: getOrCreate,
findOrInsert, fetchOrGenerate, getAndSet or computeIfAbsent write when the
resource is missing. Such compounds are refused for GET, HEAD and POST alike,
in camelCase, snake_case, kebab-case and dotted spellings, as is prose that
creates the resource when it is missing ("If the cart does not exist, a new
one is created"). A declared read-only POST body that itself asks for a write
(a GraphQL mutation, an upsert or create flag, a write action, mode or method
override, a disabled dry run) is refused by configuration validation before
any request, and the same switches in a request's query string are refused
for every request (read_path_risk).
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit


def is_loopback_target(url: str) -> bool:
    """Return True only when a target URL unambiguously names this machine.

    Accepted hosts are the exact name ``localhost`` and IP literals in a
    loopback range (127.0.0.0/8, ::1 and IPv4-mapped loopback). Everything else
    counts as remote, including look-alike names (``localhost.example.com``,
    ``127.0.0.1.nip.io``), a trailing-dot ``localhost.``, shortened, integer or
    non-ASCII IPv4 spellings, IPv6 zone indexes, user information, and any URL
    with whitespace, control characters or backslashes that parsers may read
    differently. A wrong "remote" answer only makes the caller stricter.
    """
    if not isinstance(url, str) or any(ord(character) <= 32 or ord(character) == 127 for character in url):
        return False
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        _ = parts.port  # an invalid port raises ValueError here
    except ValueError:
        return False
    if (parts.scheme not in {"http", "https"} or not hostname or not hostname.isascii()
            or "\\" in parts.netloc or "%" in hostname
            or parts.username is not None or parts.password is not None):
        return False
    if hostname == "localhost":
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


_PATH_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\\]")
_BAD_PATH_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_PATH_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_ENCODED_SLASH_EDGE = re.compile(r"(?:^|/)%2f|%2f(?:/|$)", re.IGNORECASE)


def read_path_risk(url: str) -> Optional[Dict[str, str]]:
    """Reject routing ambiguity, or a query string that asks for a write, without rewriting a concrete read URL.

    Ordinary interior encoded slashes and query data remain usable. Nested
    escapes are rejected after one decode instead of guessing a proxy's decode
    depth. Inspect controls before urlsplit can silently remove them. Every
    request the auditor sends passes through here, so a write switch in the
    query string (?upsert=true, ?_method=DELETE), whether from a specification
    default or a configured value, is refused for GET and read-only POST alike.
    """
    prefix = url.split("?", 1)[0].split("#", 1)[0]
    ambiguous = bool(_PATH_CONTROL.search(prefix))
    path = urlsplit(url).path or "/"
    if _BAD_PATH_ESCAPE.search(path) or _ENCODED_SLASH_EDGE.search(path):
        ambiguous = True
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError:
        ambiguous = True
    else:
        if (_PATH_ESCAPE.search(decoded) or _PATH_CONTROL.search(decoded)
                or "//" in decoded
                or any(part.split(";", 1)[0] in {".", ".."} for part in decoded.split("/"))):
            ambiguous = True
    if not ambiguous:
        return query_write_risk(url)
    return {
        "safety_reason": "Read-only safety policy blocked an ambiguous request path; no request was sent",
        "safety_signal": "path_ambiguity",
    }


_ACTIONS = (
    "create", "update", "delete", "remove", "assign", "convert", "send",
    "submit", "upload", "reset", "revoke", "approve", "reject", "activate",
    "deactivate", "enable", "disable", "execute", "trigger", "start", "stop",
    "cancel", "purchase", "pay", "transfer", "withdraw", "deposit", "write",
    "save", "insert", "modify", "publish", "unpublish", "enqueue", "dispatch",
    "generate", "import", "restore", "terminate", "invalidate", "schedule",
    "logout", "signout", "accept", "decline", "unsubscribe", "purge",
    "destroy", "kill", "impersonate", "confirm", "redeem", "renew", "rotate",
    "unban", "unblock", "unarchive", "unlink", "unregister", "deregister",
    "flush", "wipe", "truncate", "resend", "rerun", "reboot", "shutdown",
)
# Phrasal state-changing verbs split into two words by camelCase, snake_case or kebab-case
# (logOut, log_out, log-out, signOut, sign-out, shutDown). Plain "log" or "sign" is not matched.
_PHRASAL_ACTIONS: dict[str, tuple[str, ...]] = {
    "log out": ("log out", "logs out", "logging out"),
    "sign out": ("sign out", "signs out", "signing out"),
    "shut down": ("shut down", "shuts down", "shutting down"),
}
# Verbs that are imperative mutations in base form (/payments/{id}/refund, /jobs/{id}/run,
# /users/{id}/ban, clearCart, unlockUser), while their plural or -ing forms name ordinary
# read collections or states (/refunds, /runs, /jobs/running, /bans, /players/{id}/unlocks).
_NOUN_HOMOGRAPH_ACTIONS = (
    "refund", "clear", "ban", "run", "unlock", "retry", "restart", "abort",
)
_NOUN_METADATA_FOLLOWERS = (
    "status", "statuses", "detail", "details", "info", "information", "history",
    "log", "logs", "list", "summary", "count", "id", "ids", "record", "records",
    "result", "results", "state", "states",
)
_HOMOGRAPH_PROSE_DETERMINERS = (
    "a", "an", "the", "it", "them", "this", "that", "these", "those",
    "all", "any", "its", "current", "active", "selected", "specified",
    "target", "given", "pending", "expired", "suspended", "cached",
)
# Extra verbs that only apply to an operator-declared read-only POST. They
# exclude words whose plural is a common resource name (orders, comments,
# reports, links...), so a path such as /orders/search is not refused.
_POST_ACTIONS = _ACTIONS + (
    "add", "register", "edit", "change", "replace", "patch", "grant", "invite", "sign",
    "apply", "rename", "move", "clone", "merge",
    "sync", "refresh", "checkout", "subscribe", "follow", "unfollow",
    "attach", "detach", "login", "signin",
    "signup", "authenticate", "verify", "extend",
    "notify", "increment", "decrement", "toggle", "upsert", "append",
    "drop", "mute", "unmute", "unshare",
    "initialize", "initialise", "init", "instantiate", "allocate", "persist",
)
# A read-only POST must name one of these actions: the declaration alone is not
# accepted as evidence that a command-like POST has no side effects.
_POST_READ_INTENTS = (
    "search", "msearch", "query", "lookup", "find", "get", "mget", "list", "fetch", "retrieve",
    "read", "view", "show", "describe", "count", "filter", "browse", "inspect", "preview",
    "check", "validate", "calculate", "compute", "estimate",
)
# Identifiers (operationId, path segments) of a declared read-only POST that
# start with these name a write. Base forms only: ensureCart, provisionTenant,
# delUser, rmFile, updProfile, mkDir.
_POST_IDENTIFIER_ACTIONS = (
    "ensure", "provision", "spawn", "materialize", "materialise", "crt", "del", "rm", "upd", "mk",
)
# Verbs that turn a compound identifier into a conditional or follow-up write
# after "or", "and", "else", "then", "also" or "otherwise", wherever they occur:
# getOrCreate, findOrInsert, fetchOrGenerate, getOrInitialize, getUserAndRegister.
# Base forms only; these are rarely resource nouns in an identifier.
_COMPOUND_WRITE_VERBS = (
    "create", "crt", "insert", "ins", "upsert", "add", "save", "register", "update", "upd",
    "generate", "gen", "init", "initialize", "initialise", "instantiate", "provision", "allocate",
    "persist", "spawn", "materialize", "materialise", "ensure", "mk", "overwrite",
    # Queue and lease verbs that are not resource nouns: getNextAndDequeue,
    # fetchMessagesAndAck, listJobsAndAcknowledge, pollAndConsume.
    "dequeue", "consume", "ack", "acknowledge", "acquire",
)
# These are also nouns or adjectives ("getProductOrStore", "getUsedOrNew",
# "getCardOrSet"), so they count only directly after a read action:
# getOrSet, getAndSet, getOrPut, findAndLock, findAndClaim, findOrNew, getAndDelete,
# compareAndSet, compareAndSwap.
_ADJACENT_WRITE_VERBS = (
    "set", "put", "store", "lock", "claim", "reserve", "mint", "new", "make",
    "delete", "del", "remove", "rm", "replace", "write", "swap",
    # getOrRefreshToken, fetchOrRenewToken, getOrRotateKey; "access or refresh token" is a noun.
    "refresh", "renew", "rotate",
    # searchAndArchive, getAndMarkRead, getAndTouch. "Export" is not here: an
    # export endpoint usually downloads data ("View or export a report").
    "archive", "pop", "mark", "touch", "bump",
)
_COMPOUND_READ_ACTIONS = _POST_READ_INTENTS + ("first", "load", "compare")
# A modifier between the conjunction and the write: getOrAutoCreate,
# findOrLazyInit, getOrMaybeCreate, findOrForceInsert.
_COMPOUND_MODIFIERS = ("auto", "lazy", "lazily", "maybe", "optionally", "implicitly", "silently",
                       "conditionally", "atomically", "force", "just", "then", "else", "also")
# Prose uses these as nouns or adjectives too often ("View or mark the read
# state"); abbreviations do not occur in prose.
_PROSE_EXCLUDED_VERBS = frozenset({"new", "make", "mark", "touch", "pop", "bump",
                                   "crt", "ins", "upd", "gen", "mk", "del", "rm"})
# Objects or conditions that mark a coordinated verb in prose as the operation's
# own action: "returns the cart, or creates one if none exists".
_PROSE_OBJECTS = ("a", "an", "the", "it", "one", "them", "new", "this", "that", "these", "those",
                  "if", "when", "unless", "whenever")


def _word_forms(verbs: tuple[str, ...]) -> set[str]:
    forms = set(verbs)
    for verb in verbs:
        if len(verb) > 1 and verb.endswith("y") and verb[-2] not in "aeiou":
            forms.add(verb[:-1] + "ies")
        else:
            forms.add(verb + ("es" if verb.endswith(("s", "x", "z", "ch", "sh", "o")) else "s"))
        forms.add((verb[:-1] if verb.endswith("e") else verb) + "ing")
        if verb in {"reset", "submit", "stop", "transfer", "drop", "ban", "unban", "run", "rerun"}:
            forms.add(verb + verb[-1] + "ing")
    return forms


def _alternation(forms: set[str]) -> str:
    return r"(?:" + "|".join(sorted(forms, key=lambda word: (-len(word), word))) + r")\b"


def _third_person(verbs: tuple[str, ...]) -> set[str]:
    out: set[str] = set()
    for verb in verbs:
        if len(verb) > 1 and verb.endswith("y") and verb[-2] not in "aeiou":
            out.add(verb[:-1] + "ies")
        else:
            out.add(verb + ("es" if verb.endswith(("s", "x", "z", "ch", "sh", "o")) else "s"))
    return out


_STRONG_WRITE = _alternation(set(_COMPOUND_WRITE_VERBS))
_MODIFIER = r"(?:" + _alternation(set(_COMPOUND_MODIFIERS)) + r"\s+)?"
# A compound identifier that writes: a strong write verb after any conjunction,
# an ambiguous one directly after a read action (also behind a resource or
# controller prefix: Orders_GetOrSet, orders.getOrSet, OrdersController_getOrPut),
# either one optionally behind a modifier (getOrAutoCreate), or a conditional
# creation marker (createTableIfNotExists, computeIfAbsent, getIfAbsentPut).
_COMPOUND_WRITE = re.compile(
    r"\b(?:or|else|otherwise|and|then|also)\s+(?:it\s+)?" + _MODIFIER + _STRONG_WRITE
    + r"|\b" + _alternation(set(_COMPOUND_READ_ACTIONS)) + r"\s+(?:or|and|else)\s+" + _MODIFIER
    + _alternation(set(_ADJACENT_WRITE_VERBS))
    + r"|\bif\s+not\s+exists?\b|\bunless\s+exists?\b"
    + r"|\b(?:compute|put|" + _STRONG_WRITE + r")\s+if\s+(?:absent|missing)\b"
    + r"|\bif\s+(?:absent|missing)\s+(?:put|" + _STRONG_WRITE + r")",
    re.IGNORECASE,
)
_POST_IDENTIFIER_LEADING = re.compile(r"^" + _alternation(set(_POST_IDENTIFIER_ACTIONS)), re.IGNORECASE)
# Prose that creates the resource when it is missing ("If the cart does not
# exist, a new one is created"): a missing-resource condition and a creation in
# the same clause. A past tense ("was created by another user") or a missing
# resource alone ("Returns 404 if not found") is not a write.
_MISSING_RESOURCE = re.compile(
    r"\bnot\s+(?:yet\s+)?exists?\b|\b(?:doesn|don|didn)\s+t\s+(?:yet\s+)?exist\b|\bnone\s+exists?\b"
    r"|\bno\s+\w+(?:\s+\w+)?\s+exists?\b|\b(?:is|are)\s+(?:missing|absent)\b|\bif\s+(?:missing|absent)\b"
    r"|\bnot\s+(?:found|present)\b",
    re.IGNORECASE,
)
_CREATED_ON_DEMAND = re.compile(
    r"\b(?:is|are|gets|get|(?:will|would|shall)\s+(?:\w+ly\s+)?be)\s+(?:(?:\w+ly|then|also|first|always)\s+)?"
    r"(?:created|generated|initialized|initialised|inserted|provisioned|allocated|registered|added|issued|"
    r"made|instantiated|spawned|persisted|saved|stored|upserted)\b"
    r"|\b(?:creates|generates|initializes|initialises|inserts|provisions|allocates|instantiates|spawns|"
    r"persists|upserts)\b",
    re.IGNORECASE,
)


class _ActionPatterns:
    def __init__(self, verbs: tuple[str, ...], methods: str) -> None:
        phrasal_forms = {form for forms in _PHRASAL_ACTIONS.values() for form in forms}
        phrasal_third = {forms[1] for forms in _PHRASAL_ACTIONS.values()}
        base_word = _alternation(_word_forms(verbs) | phrasal_forms)
        identifier_word = _alternation(_word_forms(verbs) | phrasal_forms | set(_NOUN_HOMOGRAPH_ACTIONS))
        homograph_base = _alternation(set(_NOUN_HOMOGRAPH_ACTIONS))
        homograph_all = _alternation(_word_forms(_NOUN_HOMOGRAPH_ACTIONS))
        homograph_third = _alternation(_third_person(_NOUN_HOMOGRAPH_ACTIONS))
        meta_followers = _alternation(set(_NOUN_METADATA_FOLLOWERS))
        prose_det = _alternation(set(_HOMOGRAPH_PROSE_DETERMINERS))

        self.leading = re.compile(r"^" + identifier_word, re.IGNORECASE)
        self.conjoined = re.compile(
            r"\b(?:and|then|also)\s+(?:it\s+)?(?:" + identifier_word
            + r"|" + homograph_third + r"\s+" + prose_det + r")",
            re.IGNORECASE,
        )
        alternative = tuple(verb for verb in verbs + _COMPOUND_WRITE_VERBS + _ADJACENT_WRITE_VERBS
                            if verb not in _PROSE_EXCLUDED_VERBS)
        # "Get or create a cart", "Fetch or generate an API key": a read action
        # coordinated with a write at the start of a clause.
        self.alternative = re.compile(
            r"^(?:" + _alternation(_word_forms(_POST_READ_INTENTS + ("return",))) + r"|look\s+up)"
            r"\s+(?:and\s+)?or\s+" + _alternation(_word_forms(alternative) | phrasal_forms),
            re.IGNORECASE,
        )
        # "Returns the cart, or creates one if none exists": a third-person verb
        # with its own object or condition; "by email or login name" is not one.
        self.alternative_clause = re.compile(
            r"\bor\s+" + _alternation(_third_person(alternative) | phrasal_third)
            + r"\s+" + _alternation(set(_PROSE_OBJECTS)),
            re.IGNORECASE,
        )
        subject_prefix = (
            r"(?:(?:this|the)\s+(?:(?:" + methods + r")\s+)?"
            r"(?:endpoint|operation|request|api|method|" + methods + r")\s+"
            r"(?:(?:is\s+(?:used|designed|intended)\s+to|will|may|can|also|is)\s+)?"
            r"|(?:will|may|can)\s+)"
        )
        self.description = re.compile(
            r"^" + subject_prefix + r"?(?:" + base_word + r")"
            + r"|^" + subject_prefix + homograph_all
            + r"|^" + homograph_base + r"(?!\s+" + meta_followers + r")"
            + r"|^" + homograph_third + r"\s+" + prose_det,
            re.IGNORECASE,
        )
        self.informational = re.compile(
            r"^(?:" + base_word + r"|" + homograph_all
            + r")\s+(?:are|were)\s+(?:available|supported|listed|documented|possible)\b",
            re.IGNORECASE,
        )


_READ_PATTERNS = _ActionPatterns(_ACTIONS, "get|head")
_POST_PATTERNS = _ActionPatterns(_POST_ACTIONS, "get|head|post")
_LEADING_READ_INTENT = re.compile(r"^" + _alternation(_word_forms(_POST_READ_INTENTS)), re.IGNORECASE)
_LEADING_ACTION = _READ_PATTERNS.leading
_CONJOINED_ACTION = _READ_PATTERNS.conjoined


def _visible(value: str) -> str:
    """NFKC form without invisible format characters and combining marks.

    Compatibility forms (full-width letters, ligatures) read as the ASCII words
    a server router or code generator would see. A zero-width space, soft
    hyphen, word joiner or combining mark inside "Create" is dropped, not read
    as a word boundary, so it cannot hide the action word.
    """
    if value.isascii():
        return value
    value = unicodedata.normalize("NFKC", value)
    return "".join(char for char in value if unicodedata.category(char) not in ("Cf", "Mn", "Me"))


def _words(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = _visible(value)
    # Retain word boundaries for identifiers such as convertVideo/create_report,
    # including after an acronym: getORCreate, HTMLReport.
    value = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-zA-Z0-9]+", " ", value).strip().lower()


def _mixes_scripts(value: Any) -> bool:
    """True when one word mixes ASCII letters with other letters (getOrCr\u0435ate with a Cyrillic \u0435).

    The ASCII-only word split would drop the look-alike letter and with it the
    action word, so such an identifier cannot be checked.
    """
    if not isinstance(value, str):
        return False
    value = _visible(re.sub(r"\{[^}]*\}", "", value))
    for word in re.findall(r"[^\W\d_]+", value):
        ascii_letters = any(char.isascii() for char in word)
        if ascii_letters and not word.isascii():
            return True
    return False


def _mutation_signal(endpoint: Dict[str, Any], patterns: _ActionPatterns, post: bool = False) -> Tuple[str, str]:
    """The metadata field that names a write, and the rule: "action" or "compound"."""
    identifier = _words(endpoint.get("operation_id", ""))
    if patterns.leading.search(identifier) or patterns.conjoined.search(identifier) or (
            post and _POST_IDENTIFIER_LEADING.search(identifier)):
        return "operation_id", "action"
    if _COMPOUND_WRITE.search(identifier):
        return "operation_id", "compound"
    path = str(endpoint.get("path", ""))
    # Object placeholders are data, not action names.
    path = re.sub(r"\{[^}]*\}", "", path)
    segments = [_words(part) for part in path.split("/")]
    if any(patterns.leading.search(words) or (post and _POST_IDENTIFIER_LEADING.search(words))
           for words in segments):
        return "path", "action"
    if any(_COMPOUND_WRITE.search(words) for words in segments):
        return "path", "compound"
    for field in ("summary", "description"):
        value = endpoint.get(field, "")
        if not isinstance(value, str):
            continue
        # Match affirmative operation clauses, not arbitrary mentions of
        # write verbs such as "Return the report created by POST".
        clauses = re.split(r"[.!?;\n]+", value)
        words = [_words(clause) for clause in clauses]
        if any((patterns.description.search(clause)
                and not patterns.informational.search(clause))
               or patterns.conjoined.search(clause) for clause in words):
            return field, "action"
        if any(patterns.alternative.search(clause) or patterns.alternative_clause.search(clause)
               or (_MISSING_RESOURCE.search(clause) and _CREATED_ON_DEMAND.search(clause))
               for clause in words):
            return field, "compound"
    return "", ""


def _has_read_intent(endpoint: Dict[str, Any]) -> bool:
    if _LEADING_READ_INTENT.search(_words(endpoint.get("operation_id", ""))):
        return True
    path = re.sub(r"\{[^}]*\}", "", str(endpoint.get("path", "")))
    if any(_LEADING_READ_INTENT.search(_words(part)) for part in path.split("/")):
        return True
    summary = endpoint.get("summary", "")
    return isinstance(summary, str) and bool(_LEADING_READ_INTENT.search(_words(summary)))


def read_only_risk(endpoint: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return a safe-to-display signal if an operation may change state.

    GET/HEAD are refused only when their metadata explicitly suggests mutation.
    A POST is refused when its metadata uses the wider POST mutation vocabulary
    or does not name a read action. Other methods are not read operations and
    are gated by their callers. Metadata values are never echoed: specification
    prose can contain credentials or private examples. A benign summary cannot
    override a command-like path.
    """
    method = str(endpoint.get("method", "")).upper()
    if method in {"GET", "HEAD"}:
        signal, rule = _mutation_signal(endpoint, _READ_PATTERNS)
    elif method == "POST":
        if _mixes_scripts(endpoint.get("operation_id")) or _mixes_scripts(endpoint.get("path")):
            return {
                "safety_reason": "Read-only POST safety policy blocked an operationId or path that mixes ASCII and "
                                 "non-ASCII letters in one word; its action words cannot be checked; no request was sent",
                "safety_signal": "identifier_script",
            }
        signal, rule = _mutation_signal(endpoint, _POST_PATTERNS, post=True)
        if not signal and not _has_read_intent(endpoint):
            return {
                "safety_reason": "Read-only POST safety policy requires the path, operationId or summary to name a "
                                 "read action such as search, query or lookup; no request was sent",
                "safety_signal": "post_read_intent",
            }
    else:
        return None
    if not signal:
        return None
    if rule == "compound":
        return {
            "safety_reason": "Read-only safety policy blocked an operation that combines a read action with a "
                             "conditional or follow-up write (such as get-or-create, find-or-insert or "
                             "put-if-absent); no request was sent",
            "safety_signal": signal,
        }
    return {
        "safety_reason": "Read-only safety policy blocked an operation with explicit state-changing semantics; no request was sent",
        "safety_signal": signal,
    }


# Body keys whose string value selects the action a POST endpoint performs:
# {"action": "create"}, {"op": "replace"} (JSON Patch), {"operationName": "CreateUser"},
# {"mode": "upsert"}, {"operationType": "mutation"}, {"actions": ["create"]}.
_BODY_ACTION_KEYS = frozenset({
    "action", "actions", "operation", "operations", "operation name", "operation type", "op", "ops", "op type",
    "command", "commands", "cmd", "cmds", "intent", "intents", "verb", "verbs",
    "mode", "write mode", "save mode", "insert mode", "update mode",
})
# Keys that override the HTTP method (Rails, Laravel and Symfony read "_method").
_BODY_METHOD_KEYS = frozenset({"method", "http method", "method override", "x http method override",
                               "x method override", "x http method"})
_WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
# A true flag whose name starts with one of these asks the endpoint to write:
# {"upsert": true}, {"createIfMissing": true}, {"auto_create": true}, {"save_search": true}.
_BODY_FLAG_VERBS = frozenset({
    "create", "insert", "upsert", "save", "persist", "store", "commit", "write", "overwrite",
    "ensure", "init", "initialize", "initialise", "provision", "register", "delete", "purge", "destroy",
})
# Also nouns: {"store": 1} filters by store 1, so only an explicit true counts.
_BODY_FLAG_NOUNS = frozenset({"store", "register"})
# Data fields named after a verb are filters, not switches: audit columns
# ({"create_by": 1}, {"update_time": ...}) and soft-delete markers ({"delete_flag": 1}).
_BODY_FIELD_SUFFIXES = frozenset({
    "flag", "flags", "status", "state", "time", "date", "at", "on", "by", "id", "ids", "uid", "count", "type",
    "user", "users", "name", "reason", "version", "timestamp", "ts", "no", "num", "number",
})
_BODY_FLAG_PREFIXES = frozenset({"auto", "allow", "should", "do", "force", "enable", "perform"})
# A false value for one of these runs the operation for real: {"dry_run": false}.
_BODY_DRY_RUN_KEYS = frozenset({"dry run", "dryrun", "validate only", "simulate", "simulation", "what if"})
_TRUE_VALUES = frozenset({"true", "yes", "on", "1"})
_EXPLICIT_TRUE_VALUES = frozenset({"true", "yes", "on"})
_FALSE_VALUES = frozenset({"false", "no", "off", "0"})
# GraphQL names; _graphql_mutation lexes documents with them.
_GRAPHQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_LINE_END = re.compile(r"[\r\n]")
# Validated bodies are at most 64 KiB, far below this bound; it protects direct callers.
_BODY_MAX_NODES = 100000
_BODY_ACTION_VERBS = re.compile(
    r"^" + _alternation(
        _word_forms(_POST_ACTIONS + _NOUN_HOMOGRAPH_ACTIONS)
        | {form for forms in _PHRASAL_ACTIONS.values() for form in forms}
        | set(_COMPOUND_WRITE_VERBS)
        | set(_ADJACENT_WRITE_VERBS)
        | {"copy", "mutation"}
    ),
    re.IGNORECASE,
)
# Namespaced actions ("cart.create", "users:delete", "orders/bulk-insert") name
# the write in a later word; only unambiguous verbs count there.
_BODY_ACTION_ANY_WORD = (
    frozenset(_POST_ACTIONS)
    | frozenset(_NOUN_HOMOGRAPH_ACTIONS)
    | frozenset(_COMPOUND_WRITE_VERBS)
    | {"copy", "mutation"}
)


# Request headers that make a server treat a request as another method.
_METHOD_OVERRIDE_HEADERS = frozenset({"x http method override", "x http method", "x method override",
                                      "http method override", "method override"})


def method_override_risk(name: Any, value: Any) -> bool:
    """True for a configured header that turns requests into a method other than GET or HEAD.

    Identity headers are sent with every request, GET included, so an
    override to POST, PUT, PATCH or DELETE would turn reads into writes.
    """
    return (isinstance(name, str) and _words(name) in _METHOD_OVERRIDE_HEADERS
            and isinstance(value, str) and value.strip().upper() not in {"", "GET", "HEAD"})


def _body_value_is(value: Any, words: frozenset) -> bool:
    if isinstance(value, bool):
        return ("true" if value else "false") in words
    if type(value) is int:
        return str(value) in words
    if type(value) is float:
        return value in (0.0, 1.0) and str(int(value)) in words
    return isinstance(value, str) and value.strip().lower() in words


def _skip_graphql_ignored(text: str, index: int) -> int:
    """Skip GraphQL ignored tokens: white space, line ends, commas, byte order marks and comments."""
    length = len(text)
    while index < length:
        char = text[index]
        if char == "#":
            line_end = _LINE_END.search(text, index)
            index = line_end.start() if line_end else length
        elif char == "," or char == "\ufeff" or char.isspace():
            index += 1
        else:
            break
    return index


def _graphql_mutation(text: str) -> bool:
    """True when a string holds a GraphQL mutation operation.

    Lexes the text once like a GraphQL server: comments and string literals
    are skipped, so "mutation" inside them is not a keyword. The keyword must
    be followed, after ignored tokens (white space, commas, comments, byte
    order marks) and an optional name, by a selection set, variable
    definitions or a directive, and a selection set must follow somewhere:
    "mutation testing" and "mutation (genetics)" are text.
    """
    last_brace = text.rfind("{")
    if last_brace < 0 or "mutation" not in text:
        return False
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == "#":
            line_end = _LINE_END.search(text, index)
            index = line_end.start() if line_end else length
        elif char == '"':
            if text.startswith('"""', index):
                end = text.find('"""', index + 3)
                index = length if end < 0 else end + 3
            else:
                index += 1
                while index < length and text[index] not in '"\r\n':
                    index += 2 if text[index] == "\\" else 1
                index += 1
        elif char == "_" or ("a" <= char <= "z") or ("A" <= char <= "Z"):
            name = _GRAPHQL_NAME.match(text, index)
            index = name.end() if name else index + 1
            if name and name.group() == "mutation":
                after = _skip_graphql_ignored(text, index)
                operation_name = _GRAPHQL_NAME.match(text, after)
                if operation_name:
                    after = _skip_graphql_ignored(text, operation_name.end())
                if after < length and text[after] in "{(@" and last_brace >= after:
                    return True
        else:
            index += 1
    return False


def _action_names_write(value: str) -> bool:
    words = _words(value).split()
    if len(words) > 1 and words[1] == "with":
        return False  # A filter operator: startsWith, endsWith, beginsWith.
    return bool(_BODY_ACTION_VERBS.search(" ".join(words))
                or any(word in _BODY_ACTION_ANY_WORD for word in words[1:]))


def _flag_asks_for_write(key: str, value: Any) -> bool:
    words = key.split()
    while len(words) > 1 and words[0] in _BODY_FLAG_PREFIXES:
        words = words[1:]
    if not words or words[0] not in _BODY_FLAG_VERBS:
        return False
    if len(words) > 1 and words[-1] in _BODY_FIELD_SUFFIXES:
        return False  # A data field such as create_by or delete_flag.
    return _body_value_is(value, _EXPLICIT_TRUE_VALUES if words[0] in _BODY_FLAG_NOUNS else _TRUE_VALUES)


def _body_write_kind(body: Any) -> Optional[str]:
    """The kind of write a request body or query asks for, or None. Keys and values are never returned."""
    stack: List[Tuple[Any, Optional[str]]] = [(body, None)]
    nodes = 0
    while stack:
        value, key = stack.pop()
        nodes += 1
        if nodes > _BODY_MAX_NODES:
            return "more data than can be checked"
        if isinstance(value, dict):
            stack.extend((child, _words(str(name))) for name, child in value.items())
            continue
        if isinstance(value, list):
            stack.extend((child, key) for child in value)
            continue
        if isinstance(value, str):
            if _graphql_mutation(value):
                return "a GraphQL mutation"
            text = value.strip()
            if text[:1] in ("{", "[") and text[-1:] in ("}", "]"):
                # JSON sent as text ({"request": "{\"action\": \"delete\"}"}) is checked like the body.
                try:
                    stack.append((json.loads(text), key))
                    continue
                except ValueError:
                    pass
                except RecursionError:
                    return "more data than can be checked"
        if key is None:
            continue
        if key in _BODY_ACTION_KEYS:
            if isinstance(value, str) and _action_names_write(value):
                return "an action that names a write"
        elif key in _BODY_METHOD_KEYS:
            if isinstance(value, str) and value.strip().upper() in _WRITE_METHODS:
                return "an HTTP method override to PUT, PATCH or DELETE"
        elif key in _BODY_DRY_RUN_KEYS:
            if _body_value_is(value, _FALSE_VALUES):
                return "a dry-run switch turned off"
        elif _flag_asks_for_write(key, value):
            return "a flag that asks for a write"
    return None


def read_only_body_risk(body: Any) -> Optional[Dict[str, str]]:
    """Return a safe-to-display reason if a declared read-only POST body asks for a write.

    The body is the operator's own selector, sent unchanged by every identity.
    A body that selects a write cannot be read-only whatever the operation is
    called: a GraphQL mutation, an action, mode or JSON Patch "op" naming a
    write (also "cart.create", "users:delete"), an HTTP method override to
    PUT/PATCH/DELETE, a true create/upsert/save flag, or a dry-run switch turned
    off, also inside JSON sent as a string. Keys and values are never echoed.
    Ordinary filters ({"deleted": true}, {"create_by": 1}, {"delete_flag": 1},
    {"sort": "updated_at"}, {"query": "mutation testing"}) are not refused. A
    body without these markers is not proven read-only.
    """
    kind = _body_write_kind(body)
    if kind is None:
        return None
    return {"safety_reason": f"Read-only POST body contains {kind}; no request was sent",
            "safety_signal": "request_body"}


def query_write_risk(url: str) -> Optional[Dict[str, str]]:
    """Refuse a request URL whose query string asks for a write (?upsert=true, ?_method=DELETE, ?dry_run=false).

    The query rules are those of read_only_body_risk; ordinary query data
    (?page=2, ?include_deleted=true, ?store=1, ?create_time=...) is not refused.
    """
    try:
        query = urlsplit(url).query
    except ValueError:
        return None  # read_path_risk refuses what cannot be parsed.
    if not query:
        return None
    kind = _body_write_kind([{name: value} for name, value in parse_qsl(query, keep_blank_values=True)])
    if kind is None:
        return None
    return {"safety_reason": f"Read-only safety policy blocked a query string that contains {kind}; "
                             "no request was sent",
            "safety_signal": "query"}


def post_path_risk(path: str) -> Optional[Dict[str, str]]:
    """Refuse a concrete POST path whose segments, including filled values, name a mutation."""
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError:
        decoded = path
    for candidate in {path, decoded}:
        # Check matrix parameters too: a router may ignore them, a handler may not.
        # Filled values are data, so abbreviations (an id such as "rm-101") are
        # checked in the specification's path template only, not here.
        pieces = [_words(piece) for part in candidate.split("/") for piece in part.split(";")]
        if any(_POST_PATTERNS.leading.search(words) or _COMPOUND_WRITE.search(words) for words in pieces):
            return {
                "safety_reason": "Read-only safety policy blocked a POST path with explicit state-changing semantics; "
                                 "no request was sent",
                "safety_signal": "path",
            }
    return None
