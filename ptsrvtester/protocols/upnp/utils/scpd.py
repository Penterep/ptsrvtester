"""Bounded, read-only parsing of UPnP service descriptions (SCPD).

The format follows UPnP Device Architecture 1.0/2.0, section 2.5. This
module only inventories the advertised schema; it never invokes actions or
fetches URLs.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.parsers import expat

SERVICE_NS = "urn:schemas-upnp-org:service-1-0"

MAX_SCPD_BYTES = 1024 * 1024
MAX_SCPD_ELEMENTS = 5000
MAX_SCPD_DEPTH = 32
MAX_ACTIONS = 256
MAX_ARGUMENTS_PER_ACTION = 64
MAX_STATE_VARIABLES = 512
MAX_ALLOWED_VALUES = 128
MAX_FIELD_CHARS = 4096


def _parse_bounded_xml(xml_bytes: bytes) -> ET.Element:
    if not isinstance(xml_bytes, bytes) or not xml_bytes or len(xml_bytes) > MAX_SCPD_BYTES:
        raise ValueError("SCPD XML is empty or exceeds size limit")

    guard = expat.ParserCreate()
    elements = 0
    depth = 0

    def reject_declaration(*_args):
        raise ValueError("DTD and entity declarations are not allowed in SCPD XML")

    def start_element(_name, _attrs):
        nonlocal elements, depth
        elements += 1
        depth += 1
        if elements > MAX_SCPD_ELEMENTS or depth > MAX_SCPD_DEPTH:
            raise ValueError("SCPD XML structure exceeds limits")

    def end_element(_name):
        nonlocal depth
        depth -= 1

    guard.StartDoctypeDeclHandler = reject_declaration
    guard.EntityDeclHandler = reject_declaration
    guard.ExternalEntityRefHandler = reject_declaration
    guard.StartElementHandler = start_element
    guard.EndElementHandler = end_element
    try:
        guard.Parse(xml_bytes, True)
        return ET.fromstring(xml_bytes)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError(f"invalid SCPD XML: {exc}") from exc


def _one(parent: ET.Element, name: str, namespace: str, *, required: bool = False) -> ET.Element | None:
    tag = f"{{{namespace}}}{name}" if namespace else name
    children = [child for child in parent if child.tag == tag]
    if len(children) > 1:
        raise ValueError(f"SCPD XML has duplicate {name}")
    if not children:
        if required:
            raise ValueError(f"SCPD XML is missing {name}")
        return None
    return children[0]


def _field(
    parent: ET.Element,
    name: str,
    namespace: str,
    *,
    required: bool = False,
    max_chars: int = MAX_FIELD_CHARS,
    strip: bool = True,
) -> str | None:
    element = _one(parent, name, namespace, required=required)
    if element is None:
        return None
    if len(element):
        raise ValueError(f"SCPD {name} must contain text only")
    value = element.text or ""
    if strip:
        value = value.strip()
    if len(value) > max_chars:
        raise ValueError(f"SCPD {name} exceeds text limit")
    if required and not value:
        raise ValueError(f"SCPD {name} is empty")
    return value


def _attribute(element: ET.Element, name: str, *, max_chars: int = 128) -> str | None:
    value = element.get(name)
    if value is not None and len(value) > max_chars:
        raise ValueError(f"SCPD {name} attribute exceeds text limit")
    return value


def _yes_no_attribute(element: ET.Element, name: str, default: bool) -> bool:
    value = _attribute(element, name)
    if value is None:
        return default
    if value.lower() not in ("yes", "no"):
        raise ValueError(f"SCPD {name} attribute must be yes or no")
    return value.lower() == "yes"


def _parse_argument(element: ET.Element, namespace: str) -> dict:
    direction = _field(element, "direction", namespace, required=True, max_chars=16)
    if direction not in ("in", "out"):
        raise ValueError("SCPD argument direction must be in or out")
    return {
        "name": _field(element, "name", namespace, required=True, max_chars=256),
        "direction": direction,
        "relatedStateVariable": _field(
            element, "relatedStateVariable", namespace, required=True, max_chars=256
        ),
        "retval": _one(element, "retval", namespace) is not None,
    }


def _parse_action(element: ET.Element, namespace: str) -> dict:
    arguments = []
    argument_list = _one(element, "argumentList", namespace)
    if argument_list is not None:
        argument_tag = f"{{{namespace}}}argument" if namespace else "argument"
        for argument in argument_list:
            if argument.tag == argument_tag:
                if len(arguments) >= MAX_ARGUMENTS_PER_ACTION:
                    raise ValueError("SCPD action has too many arguments")
                arguments.append(_parse_argument(argument, namespace))
    return {
        "name": _field(element, "name", namespace, required=True, max_chars=256),
        "arguments": arguments,
    }


def _parse_state_variable(element: ET.Element, namespace: str) -> dict:
    data_type = _one(element, "dataType", namespace, required=True)
    assert data_type is not None
    allowed_value_list = _one(element, "allowedValueList", namespace)
    allowed_values = None
    if allowed_value_list is not None:
        allowed_values = []
        value_tag = f"{{{namespace}}}allowedValue" if namespace else "allowedValue"
        for value in allowed_value_list:
            if value.tag == value_tag:
                if len(allowed_values) >= MAX_ALLOWED_VALUES:
                    raise ValueError("SCPD state variable has too many allowed values")
                if len(value):
                    raise ValueError("SCPD allowedValue must contain text only")
                text = value.text or ""
                if len(text) > MAX_FIELD_CHARS:
                    raise ValueError("SCPD allowedValue exceeds text limit")
                allowed_values.append(text)

    allowed_range = _one(element, "allowedValueRange", namespace)
    parsed_range = None
    if allowed_range is not None:
        parsed_range = {
            "minimum": _field(allowed_range, "minimum", namespace, required=True),
            "maximum": _field(allowed_range, "maximum", namespace, required=True),
            "step": _field(allowed_range, "step", namespace),
        }
    if allowed_values is not None and parsed_range is not None:
        raise ValueError("SCPD state variable has both allowedValueList and allowedValueRange")

    return {
        "name": _field(element, "name", namespace, required=True, max_chars=256),
        "dataType": _field(element, "dataType", namespace, required=True, max_chars=256),
        "dataTypeType": _attribute(data_type, "type", max_chars=256),
        "sendEvents": _yes_no_attribute(element, "sendEvents", True),
        "multicast": _yes_no_attribute(element, "multicast", False),
        "defaultValue": _field(element, "defaultValue", namespace, strip=False),
        "allowedValues": allowed_values,
        "allowedValueRange": parsed_range,
    }


def parse_service_description(xml_bytes: bytes) -> dict:
    """Return an ordered, JSON-serializable action and state-variable inventory.

    The UPnP namespace is expected, but unnamespaced SCPD is accepted for
    interoperability with older devices. Vendor extension elements are ignored.
    Malformed or over-limit documents raise ``ValueError``.
    """
    root = _parse_bounded_xml(xml_bytes)
    if root.tag == f"{{{SERVICE_NS}}}scpd":
        namespace = SERVICE_NS
    elif root.tag == "scpd":
        namespace = ""
    else:
        raise ValueError("XML root is not a UPnP service description")

    version = _one(root, "specVersion", namespace, required=True)
    assert version is not None
    action_list = _one(root, "actionList", namespace)
    actions = []
    if action_list is not None:
        action_tag = f"{{{namespace}}}action" if namespace else "action"
        for action in action_list:
            if action.tag == action_tag:
                if len(actions) >= MAX_ACTIONS:
                    raise ValueError("SCPD has too many actions")
                actions.append(_parse_action(action, namespace))

    state_table = _one(root, "serviceStateTable", namespace, required=True)
    assert state_table is not None
    state_tag = f"{{{namespace}}}stateVariable" if namespace else "stateVariable"
    state_variables = []
    for state in state_table:
        if state.tag == state_tag:
            if len(state_variables) >= MAX_STATE_VARIABLES:
                raise ValueError("SCPD has too many state variables")
            state_variables.append(_parse_state_variable(state, namespace))
    if not state_variables:
        raise ValueError("SCPD serviceStateTable has no state variables")

    return {
        "configId": _attribute(root, "configId", max_chars=64),
        "specVersion": {
            "major": _field(version, "major", namespace, required=True, max_chars=16),
            "minor": _field(version, "minor", namespace, required=True, max_chars=16),
        },
        "actions": actions,
        "stateVariables": state_variables,
    }
