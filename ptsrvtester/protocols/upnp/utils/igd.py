"""Small, bounded SOAP helpers for read-only UPnP IGD actions.

The wire format follows UPnP Device Architecture 1.0, section 3.2, and the
WANIPConnection:1/:2 and WANPPPConnection:1 service definitions. Transport and
target scoping belong to the caller; these helpers do not make network calls.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Mapping
from xml.parsers import expat
from xml.sax.saxutils import escape

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP_ENCODING_NS = "http://schemas.xmlsoap.org/soap/encoding/"
UPNP_CONTROL_NS = "urn:schemas-upnp-org:control-1-0"

SUPPORTED_SERVICE_TYPES = frozenset({
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
})

# IN and OUT arguments in the order given by the IGD service specifications.
ACTION_ARGUMENTS = {
    "GetStatusInfo": (
        (),
        ("NewConnectionStatus", "NewLastConnectionError", "NewUptime"),
    ),
    "GetNATRSIPStatus": (
        (),
        ("NewRSIPAvailable", "NewNATEnabled"),
    ),
    "GetExternalIPAddress": ((), ("NewExternalIPAddress",)),
    "GetGenericPortMappingEntry": (
        ("NewPortMappingIndex",),
        (
            "NewRemoteHost", "NewExternalPort", "NewProtocol",
            "NewInternalPort", "NewInternalClient", "NewEnabled",
            "NewPortMappingDescription", "NewLeaseDuration",
        ),
    ),
}

MAX_SOAP_BYTES = 256 * 1024
MAX_SOAP_ELEMENTS = 256
MAX_SOAP_DEPTH = 16


class SoapFault(Exception):
    """A valid UPnP SOAP fault returned by a service."""

    def __init__(self, code: int, description: str | None = None):
        self.code = code
        self.error_code = code
        self.description = description
        super().__init__(f"UPnP error {code}: {description or 'no description'}")


def _check_action(action: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        return ACTION_ARGUMENTS[action]
    except (KeyError, TypeError) as exc:
        raise ValueError("UPnP IGD action is not allowlisted") from exc


def build_soap_request(
    service_type: str, action: str, arguments: Mapping[str, str | int]
) -> bytes:
    """Return a SOAP 1.1 body for an allowlisted, read-only IGD action.

    The caller sets ``SOAPACTION: "<service_type>#<action>"`` and sends this
    body in an HTTP POST to the service's validated controlURL.
    """
    if service_type not in SUPPORTED_SERVICE_TYPES:
        raise ValueError("UPnP IGD service type is not allowlisted")
    in_names, _ = _check_action(action)
    if not isinstance(arguments, Mapping) or set(arguments) != set(in_names):
        raise ValueError(f"{action} requires exactly these arguments: {in_names}")

    values: list[str] = []
    for name in in_names:
        value = arguments[name]
        if name == "NewPortMappingIndex":
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise ValueError("NewPortMappingIndex must be an integer from 0 to 65535")
            digits = str(value)
            if not digits or len(digits) > 5 or any(char not in "0123456789" for char in digits):
                raise ValueError("NewPortMappingIndex must be an integer from 0 to 65535")
            number = int(digits)
            if number > 65535:
                raise ValueError("NewPortMappingIndex must be an integer from 0 to 65535")
            value = str(number)
        values.append(f"<{name}>{escape(value)}</{name}>")

    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{SOAP_NS}" '
        f's:encodingStyle="{SOAP_ENCODING_NS}">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">'
        f'{"".join(values)}'
        f'</u:{action}></s:Body></s:Envelope>'
    ).encode()
    return body


def _parse_bounded_xml(xml_bytes: bytes) -> ET.Element:
    if not isinstance(xml_bytes, bytes) or not xml_bytes or len(xml_bytes) > MAX_SOAP_BYTES:
        raise ValueError("SOAP response is empty or exceeds size limit")
    guard = expat.ParserCreate()
    elements = 0
    depth = 0

    def reject_declaration(*_args):
        raise ValueError("DTD and entity declarations are not allowed in SOAP")

    def start_element(_name, _attrs):
        nonlocal elements, depth
        elements += 1
        depth += 1
        if elements > MAX_SOAP_ELEMENTS or depth > MAX_SOAP_DEPTH:
            raise ValueError("SOAP XML structure exceeds limits")

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
        raise ValueError(f"invalid SOAP XML: {exc}") from exc


def _single(parent: ET.Element, name: str) -> ET.Element:
    children = [child for child in parent if child.tag == name]
    if len(children) != 1:
        raise ValueError(f"SOAP response must contain exactly one {name}")
    return children[0]


def _read_fault(element: ET.Element) -> SoapFault:
    details = [child for child in element if child.tag.rsplit("}", 1)[-1] == "detail"]
    if len(details) != 1:
        raise ValueError("SOAP fault is missing detail")
    upnp_error = _single(details[0], f"{{{UPNP_CONTROL_NS}}}UPnPError")
    code_element = _single(upnp_error, f"{{{UPNP_CONTROL_NS}}}errorCode")
    raw_code = code_element.text or ""
    if not raw_code.isascii() or not raw_code.isdecimal() or len(raw_code) > 5:
        raise ValueError("SOAP fault has an invalid UPnP error code")
    descriptions = [
        child for child in upnp_error
        if child.tag == f"{{{UPNP_CONTROL_NS}}}errorDescription"
    ]
    if len(descriptions) > 1:
        raise ValueError("SOAP fault has duplicate error descriptions")
    description = descriptions[0].text if descriptions else None
    if description is not None and len(description) > 512:
        raise ValueError("SOAP fault description exceeds size limit")
    return SoapFault(int(raw_code), description)


def parse_soap_response(
    xml_bytes: bytes, action: str, service_type: str | None = None
) -> dict[str, str]:
    """Extract scalar OUT arguments from a bounded SOAP 1.1 IGD response.

    Supplying ``service_type`` also checks that the response uses the service
    namespace advertised by the device. UPnP faults raise :class:`SoapFault`.
    """
    _, out_names = _check_action(action)
    if service_type is not None and service_type not in SUPPORTED_SERVICE_TYPES:
        raise ValueError("UPnP IGD service type is not allowlisted")
    root = _parse_bounded_xml(xml_bytes)
    if root.tag != f"{{{SOAP_NS}}}Envelope":
        raise ValueError("SOAP response has an invalid envelope")
    body = _single(root, f"{{{SOAP_NS}}}Body")
    if len(body) != 1:
        raise ValueError("SOAP body must contain exactly one response or fault")
    result = body[0]
    if result.tag == f"{{{SOAP_NS}}}Fault":
        raise _read_fault(result)
    namespaces = (service_type,) if service_type is not None else SUPPORTED_SERVICE_TYPES
    if result.tag not in {f"{{{namespace}}}{action}Response" for namespace in namespaces}:
        raise ValueError("SOAP action response has an unexpected name or service namespace")
    response_namespace = result.tag.split("}", 1)[0][1:]
    fields: dict[str, str] = {}
    for child in result:
        if child.tag.startswith("{"):
            namespace, field_name = child.tag[1:].split("}", 1)
            if namespace != response_namespace:
                continue
        else:
            field_name = child.tag
        if field_name not in out_names:
            continue
        if field_name in fields or len(child):
            raise ValueError(f"SOAP response has duplicate or complex {field_name}")
        fields[field_name] = child.text or ""
    missing = set(out_names) - fields.keys()
    if missing:
        raise ValueError(f"SOAP response is missing {', '.join(sorted(missing))}")
    return fields
