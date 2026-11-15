"""How the GitHub Actions runner reads workflow commands from a step's output.

A model of ``ActionCommand.TryParseV2``, ``ActionCommand.TryParse`` and
``ActionCommandManager.TryProcessCommand`` in actions/runner, for tests that
check which text in a log the runner would execute:

* output is split into lines at CR LF, LF or CR (.NET ``ReadLine``), on stdout
  and stderr alike;
* ``::command properties::data`` counts after leading whitespace (.NET
  ``TrimStart``);
* the legacy ``##[command properties]data`` counts anywhere in a line;
* only registered command names count; ``::stop-commands::TOKEN`` registers
  TOKEN and ignores every command until ``::TOKEN::``.

The runner compares the prefixes with culture-sensitive .NET string functions;
the model compares ordinally, which matches for the ASCII text these tests
inspect.
"""

from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional, Set

REGISTERED = frozenset({
    "set-env", "set-output", "save-state", "add-mask", "add-path", "add-matcher", "remove-matcher", "debug",
    "warning", "error", "notice", "group", "endgroup", "echo", "stop-commands", "internal-set-repo-path",
})
# Characters .NET char.IsWhiteSpace accepts.
DOTNET_WHITESPACE = frozenset("\t\n\v\f\r \x85\xa0          "
                              "      　")


class Command(NamedTuple):
    name: str
    properties: Dict[str, str]
    data: str
    line: str


def _unescape_data(value: str) -> str:
    return value.replace("%0D", "\r").replace("%0A", "\n").replace("%25", "%")


def _unescape_property(value: str) -> str:
    return (value.replace("%0D", "\r").replace("%0A", "\n").replace("%3A", ":").replace("%2C", ",")
            .replace("%25", "%"))


def _parse_v2(line: str, registered: Set[str]) -> Optional[Command]:
    start = 0
    while start < len(line) and line[start] in DOTNET_WHITESPACE:
        start += 1
    message = line[start:]
    if not message.startswith("::"):
        return None
    end = message.find("::", 2)
    if end < 0:
        return None
    info = message[2:end]
    name, _, rest = info.partition(" ")
    if name not in registered:
        return None
    properties = {}
    for pair in rest.strip().split(","):
        key, separator, value = pair.partition("=")
        if separator and key and value:
            properties[key] = _unescape_property(value)
    return Command(name, properties, _unescape_data(message[end + 2:]), line)


def _parse_legacy(line: str, registered: Set[str]) -> Optional[Command]:
    start = line.find("##[")
    if start < 0:
        return None
    close = line.find("]", start)
    if close < 0:
        return None
    info = line[start + 3:close]
    name, _, rest = info.partition(" ")
    if name not in registered:
        return None
    properties = {}
    for pair in rest.split(";"):
        key, separator, value = pair.partition("=")
        if separator and key and value:
            properties[key] = value
    return Command(name, properties, line[close + 1:], line)


def runner_commands(log: str) -> List[Command]:
    """The commands the runner would execute for this output, in order.

    Pausing and resuming are reported as the commands ``stop-commands`` and
    ``resume``.
    """
    executed: List[Command] = []
    token: Optional[str] = None
    for line in re.split(r"\r\n|\n|\r", log):
        registered = set(REGISTERED) | ({token} if token else set())
        command = _parse_v2(line, registered) or _parse_legacy(line, registered)
        if command is None:
            continue
        if token is not None:
            if command.name.lower() == token.lower():
                executed.append(Command("resume", {}, "", line))
                token = None
            continue
        if command.name == "stop-commands":
            token = command.data
        executed.append(command)
    return executed
