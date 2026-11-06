"""Bounded YAML loading for OpenAPI documents from untrusted sources.

YAML anchors and aliases let one parsed node stand for many references.
PyYAML expands merge keys (``<<``) while constructing Python objects, and the
schema resolver later walks every reference separately, so a document of a
few hundred bytes can expand exponentially and stall loading for minutes.

The composed node graph is checked before any object is constructed. Composing
is linear in the document size and aliases are still shared nodes there, so
the expanded size can be computed cheaply. Like a decompression-ratio check,
aliases may add at most ``max(MAX_ALIAS_EXPANSION_NODES,
MAX_ALIAS_EXPANSION_RATIO * own_nodes)`` nodes beyond the document's own
nodes, so later processing stays proportional to the input. Recursive aliases
are rejected. Documents without aliases are never limited, however large.
"""

from __future__ import annotations

from typing import IO, Any, Dict, List, Set, Tuple, Union

# Floor for small documents: downstream processing costs roughly 4 us per
# expanded node, so this bounds an exponential "alias bomb" to about a second.
MAX_ALIAS_EXPANSION_NODES = 250_000
# Large documents legitimately reuse blocks: yaml.safe_dump emits an alias for
# every repeated Python object, e.g. one shared schema across many operations.
MAX_ALIAS_EXPANSION_RATIO = 10


class YAMLAliasExpansionError(ValueError):
    """YAML aliases expand beyond the supported bound or refer to themselves."""


def _children(node: Any) -> List[Any]:
    value = node.value
    if not isinstance(value, list):
        return []  # A scalar node holds its text.
    children: List[Any] = []
    for item in value:
        if isinstance(item, tuple):  # Mapping nodes hold (key, value) pairs.
            children.extend(item)
        else:
            children.append(item)
    return children


def check_alias_expansion(
    root: Any, limit: int = MAX_ALIAS_EXPANSION_NODES, ratio: int = MAX_ALIAS_EXPANSION_RATIO,
) -> None:
    """Reject a composed YAML node graph whose aliases add too many nodes.

    Aliases may add ``max(limit, ratio * own_nodes)`` nodes, where
    ``own_nodes`` counts each distinct node of the document once.

    Iterative post-order traversal with memoized subtree sizes: each distinct
    node is visited once, so the check is linear in the document size even
    when its expanded size is astronomically large.
    """
    sizes: Dict[int, int] = {}
    active: Set[int] = set()  # Nodes on the current traversal path.
    stack: List[Tuple[Any, bool]] = [(root, False)]
    while stack:
        node, finished = stack.pop()
        key = id(node)
        if finished:
            sizes[key] = 1 + sum(sizes[id(child)] for child in _children(node))
            active.discard(key)
            continue
        if key in sizes:
            continue
        if key in active:
            raise YAMLAliasExpansionError(
                "Recursive YAML aliases are not supported in OpenAPI documents; no request was sent"
            )
        active.add(key)
        stack.append((node, True))
        stack.extend((child, False) for child in _children(node))
    own_nodes = len(sizes)
    allowed = max(limit, ratio * own_nodes)
    if sizes[id(root)] - own_nodes > allowed:
        raise YAMLAliasExpansionError(
            f"YAML aliases expand the document by more than {allowed} nodes; "
            "reduce anchor/alias reuse or use $ref instead; no request was sent"
        )


def safe_load_yaml(stream: Union[str, bytes, IO[str]]) -> Any:
    """``yaml.safe_load`` with the alias expansion check before construction."""
    import yaml

    loader = yaml.SafeLoader(stream)
    try:
        node = loader.get_single_node()
        if node is None:
            return None
        check_alias_expansion(node)
        return loader.construct_document(node)
    finally:
        loader.dispose()
