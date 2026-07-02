"""Lightweight SAML XML parsing helpers.

Mirrors `reference/packages/sso/src/saml/parser.ts`, which wraps
`fast-xml-parser` configured with::

    new XMLParser({
        ignoreAttributes: false,
        attributeNamePrefix: "@_",
        removeNSPrefix: true,
        processEntities: false,
    })

We reproduce the same dict shape using ``lxml``: every element is keyed by its
*local* name (namespace prefix stripped), attributes are stored under
``@_<name>`` keys, and repeated sibling elements collapse into a list. Text
content is stored under ``#text`` when an element has both attributes/children
and text — matching fast-xml-parser — though the structural walkers below only
care about element nesting.

The two exported walkers, :func:`find_node` and :func:`count_all_nodes`, operate
on that dict exactly like their TS counterparts.
"""

from __future__ import annotations

from typing import Any

from lxml import etree


def _local_name(tag: Any) -> str | None:
    """Return the namespace-stripped local name of an lxml tag.

    Comments / processing instructions have a callable ``tag`` in lxml; those
    are skipped (return ``None``).
    """
    if not isinstance(tag, str):
        return None
    # Declared namespaces produce Clark notation: "{uri}local".
    if "}" in tag:
        tag = tag.rsplit("}", 1)[1]
    # Undeclared prefixes (tolerated via recover mode) keep "prefix:local"
    # form; fast-xml-parser strips these textually, so we do too.
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag


def _element_to_dict(el: etree._Element) -> Any:
    """Convert one element into the fast-xml-parser-style value."""
    node: dict[str, Any] = {}

    for name, value in el.attrib.items():
        local = name.rsplit("}", 1)[1] if "}" in name else name
        if ":" in local:
            local = local.rsplit(":", 1)[1]
        node[f"@_{local}"] = value

    for child in el:
        local = _local_name(child.tag)
        if local is None:
            continue
        child_value = _element_to_dict(child)
        if local in node:
            existing = node[local]
            if isinstance(existing, list):
                existing.append(child_value)
            else:
                node[local] = [existing, child_value]
        else:
            node[local] = child_value

    text = (el.text or "").strip()
    if not node:
        # Leaf element: represent as its text (or empty string).
        return text
    if text:
        node["#text"] = text
    return node


def parse_xml(xml: str) -> dict[str, Any]:
    """Parse an XML string into a fast-xml-parser-style nested dict.

    Raises ``etree.XMLSyntaxError`` on malformed input (callers catch broadly,
    matching the TS ``try/catch`` semantics).
    """
    # fast-xml-parser is a non-validating parser: it strips namespace prefixes
    # textually and never errors on *undeclared* prefixes. lxml's strict mode
    # rejects those, so we run in recover mode to match that tolerance while
    # still surfacing genuinely unparseable input (root is None).
    parser = etree.XMLParser(resolve_entities=False, recover=True)
    root = etree.fromstring(xml.encode("utf-8"), parser=parser)
    if root is None:
        raise etree.XMLSyntaxError("Document is not well formed", "", 0, 0)
    local = _local_name(root.tag)
    return {local: _element_to_dict(root)}


def find_node(obj: Any, node_name: str) -> Any:
    """Depth-first search for the first value keyed ``node_name``.

    Mirrors the TS ``findNode``: returns the node's value (dict / list / str)
    or ``None`` when absent.
    """
    if not isinstance(obj, dict):
        return None

    if node_name in obj:
        return obj[node_name]

    for value in obj.values():
        if isinstance(value, list):
            for item in value:
                found = find_node(item, node_name)
                if found:
                    return found
        elif isinstance(value, dict):
            found = find_node(value, node_name)
            if found:
                return found

    return None


def count_all_nodes(obj: Any, node_name: str) -> int:
    """Count every occurrence of ``node_name`` anywhere in the tree.

    Mirrors the TS ``countAllNodes``: a list value contributes its length.
    """
    if not isinstance(obj, dict):
        return 0

    count = 0
    if node_name in obj:
        node = obj[node_name]
        count += len(node) if isinstance(node, list) else 1

    for value in obj.values():
        if isinstance(value, list):
            for item in value:
                count += count_all_nodes(item, node_name)
        elif isinstance(value, dict):
            count += count_all_nodes(value, node_name)

    return count


__all__ = ["count_all_nodes", "find_node", "parse_xml"]
