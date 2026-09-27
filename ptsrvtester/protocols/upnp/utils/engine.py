"""Bounded, target-scoped SSDP discovery and UPnP device descriptions."""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import threading
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit
from xml.parsers import expat

from .igd import (
    MAX_SOAP_BYTES,
    SUPPORTED_SERVICE_TYPES,
    SoapFault,
    build_soap_request,
    parse_soap_response,
)
from .multicast import MULTICAST_ADDRESS, MULTICAST_PORT, build_multicast_msearch
from .scpd import parse_service_description

MAX_DATAGRAM_BYTES = 8192
MAX_XML_ELEMENTS = 5000
MAX_XML_NESTING = 64
MAX_DEVICE_DEPTH = 16
MAX_LOCATION_LENGTH = 2048
MAX_DESCRIPTION_FETCHES = 50
MAX_TOTAL_DESCRIPTION_BYTES = 32 * 1024 * 1024
MAX_IGD_SERVICES = 5
MAX_IGD_SERVICE_CANDIDATES = 20
MAX_TOTAL_SOAP_BYTES = 32 * 1024 * 1024
MAX_MULTICAST_DATAGRAMS = 20_000
MAX_SCPD_SERVICE_CANDIDATES = 100
MAX_SCPD_BYTES = 256 * 1024
MAX_TOTAL_SCPD_BYTES = 8 * 1024 * 1024
IGD_INFO_ACTIONS = (
    "GetStatusInfo", "GetNATRSIPStatus", "GetExternalIPAddress",
)
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d+)\s*(?:,|$)", re.IGNORECASE)


class OutOfScopeLocation(ValueError):
    """A device description URL is outside the selected target."""


class HttpAccessDenied(Exception):
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"HTTP {status} access denied")


class SoapBudgetExceeded(Exception):
    """The shared response budget for read-only IGD requests has been reached."""


class ResponseSizeExceeded(ValueError):
    """A bounded HTTP read exceeded its cap; retain bytes read for accounting."""

    def __init__(self, read_bytes: int = 0):
        self.read_bytes = read_bytes
        super().__init__("HTTP response exceeds size limit")


def build_msearch(search_target: str, host: str, port: int) -> bytes:
    """Build the unicast M-SEARCH form from UPnP Device Architecture 2.0."""
    if not search_target or any(ord(char) < 33 or ord(char) > 126 for char in search_target):
        raise ValueError("search target must contain visible ASCII without spaces")
    if not 1 <= port <= 65535:
        raise ValueError("UDP port must be between 1 and 65535")
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"ST: {search_target}\r\n"
        "\r\n"
    ).encode("ascii")


def parse_ssdp_response(packet: bytes, source: tuple) -> dict:
    """Keep response evidence even when a peer sends malformed SSDP headers."""
    result = {
        "sourceIp": str(source[0]),
        "sourcePort": int(source[1]),
        "st": None,
        "usn": None,
        "location": None,
        "server": None,
        "cacheMaxAge": None,
        "bootId": None,
        "configId": None,
        "valid": False,
        "validationErrors": [],
        "warnings": [],
    }
    errors = result["validationErrors"]
    warnings = result["warnings"]
    if len(packet) > MAX_DATAGRAM_BYTES:
        errors.append("response_too_large")
        return result
    if b"\x00" in packet:
        errors.append("nul_byte")
        return result
    text = packet.decode("iso-8859-1")
    lines = text.split("\r\n")
    if not lines or lines[0].strip() != "HTTP/1.1 200 OK":
        errors.append("invalid_status_line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line or line[0] in " \t":
            errors.append("invalid_header")
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or any(ord(char) < 33 or ord(char) > 126 for char in name):
            errors.append("invalid_header_name")
            continue
        if name in headers and headers[name] != value:
            errors.append(f"duplicate_{name}")
            continue
        headers[name] = value

    for field, header in (
        ("st", "st"),
        ("usn", "usn"),
        ("location", "location"),
        ("server", "server"),
        ("bootId", "bootid.upnp.org"),
        ("configId", "configid.upnp.org"),
    ):
        result[field] = headers.get(header)
    for required in ("st", "usn", "location"):
        if not result[required]:
            errors.append(f"missing_{required}")
    for recommended in ("server", "cache-control", "ext"):
        if recommended not in headers:
            warnings.append(f"missing_{recommended.replace('-', '_')}")

    cache_control = headers.get("cache-control", "")
    match = _MAX_AGE.search(cache_control)
    if match and len(match.group(1)) <= 20:
        result["cacheMaxAge"] = int(match.group(1))
    elif cache_control:
        warnings.append("invalid_cache_control")
    location = result["location"]
    if location:
        try:
            parsed = urlsplit(location)
            if (
                len(location) > MAX_LOCATION_LENGTH
                or parsed.scheme.lower() not in ("http", "https")
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                errors.append("invalid_location")
            else:
                port = parsed.port
                if port is not None and not 1 <= port <= 65535:
                    errors.append("invalid_location")
        except ValueError:
            errors.append("invalid_location")
    result["valid"] = not errors
    return result


def _child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            value = (child.text or "").strip()
            return value or None
    return None


def _child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            return child
    return None


def parse_device_description(xml_bytes: bytes, location: str) -> dict:
    """Extract a bounded device/service inventory without fetching service URLs."""
    if len(xml_bytes) > 16 * 1024 * 1024:
        raise ValueError("device XML exceeds hard size limit")
    guard = expat.ParserCreate()
    elements = 0
    depth = 0

    def reject_dtd(*_args):
        raise ValueError("DTD and entity declarations are not allowed")

    def start_element(_name, _attrs):
        nonlocal elements, depth
        elements += 1
        depth += 1
        if elements > MAX_XML_ELEMENTS or depth > MAX_XML_NESTING:
            raise ValueError("device XML structure exceeds limits")

    def end_element(_name):
        nonlocal depth
        depth -= 1

    guard.StartDoctypeDeclHandler = reject_dtd
    guard.EntityDeclHandler = reject_dtd
    guard.ExternalEntityRefHandler = reject_dtd
    guard.StartElementHandler = start_element
    guard.EndElementHandler = end_element
    try:
        guard.Parse(xml_bytes, True)
    except expat.ExpatError as exc:
        raise ValueError(f"invalid device XML: {exc}") from exc
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"invalid device XML: {exc}") from exc
    if root.tag.rsplit("}", 1)[-1] != "root":
        raise ValueError("XML root is not a UPnP device description")
    element_count = sum(1 for _ in root.iter())
    if element_count > MAX_XML_ELEMENTS:
        raise ValueError("device XML has too many elements")
    device_element = _child(root, "device")
    if device_element is None:
        raise ValueError("device description has no root device")
    url_base = _child_text(root, "URLBase")
    try:
        base_scheme = urlsplit(url_base).scheme if url_base else ""
    except ValueError:
        base_scheme = ""
    base = url_base if base_scheme in ("http", "https") else location

    def absolute_url(value: str | None) -> str | None:
        return urljoin(base, value) if value else None

    def parse_device(element: ET.Element, depth: int = 0) -> dict:
        if depth > MAX_DEVICE_DEPTH:
            raise ValueError("device XML nesting limit exceeded")
        device = {
            "deviceType": _child_text(element, "deviceType"),
            "friendlyName": _child_text(element, "friendlyName"),
            "manufacturer": _child_text(element, "manufacturer"),
            "modelName": _child_text(element, "modelName"),
            "modelNumber": _child_text(element, "modelNumber"),
            "serialNumber": _child_text(element, "serialNumber"),
            "udn": _child_text(element, "UDN"),
            "presentationUrl": absolute_url(_child_text(element, "presentationURL")),
            "services": [],
            "embeddedDevices": [],
        }
        service_list = _child(element, "serviceList")
        if service_list is not None:
            for service in service_list:
                if service.tag.rsplit("}", 1)[-1] != "service":
                    continue
                scpd = _child_text(service, "SCPDURL")
                control = _child_text(service, "controlURL")
                event = _child_text(service, "eventSubURL")
                device["services"].append({
                    "serviceType": _child_text(service, "serviceType"),
                    "serviceId": _child_text(service, "serviceId"),
                    "scpdUrl": absolute_url(scpd),
                    "controlUrl": absolute_url(control),
                    "eventSubUrl": absolute_url(event),
                    "scpdUrlRaw": scpd,
                    "controlUrlRaw": control,
                    "eventSubUrlRaw": event,
                })
        device_list = _child(element, "deviceList")
        if device_list is not None:
            for embedded in device_list:
                if embedded.tag.rsplit("}", 1)[-1] == "device":
                    device["embeddedDevices"].append(parse_device(embedded, depth + 1))
        return device

    version = _child(root, "specVersion")
    return {
        "location": location,
        "urlBase": url_base,
        "specVersion": {
            "major": _child_text(version, "major") if version is not None else None,
            "minor": _child_text(version, "minor") if version is not None else None,
        },
        "device": parse_device(device_element),
    }


def _all_udns(device: dict) -> set[str]:
    found: set[str] = set()
    pending = [device]
    while pending:
        current = pending.pop()
        if current["udn"]:
            found.add(current["udn"].lower())
        pending.extend(current["embeddedDevices"])
    return found


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the discovered IP while verifying the advertised TLS name."""

    def __init__(self, host: str, connect_ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self):
        sock = socket.create_connection(
            (self._connect_ip, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class UpnpEngine:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.target_ip = str(args._upnp_resolved_ip)
        self.target_host = str(args._upnp_target_host)
        self.port = int(args.target.port or 1900)
        self.discoveries: list[dict] = []
        self.devices: list[dict] = []
        self.module_errors: list[dict] = []
        self.discovery_status = "not_run"
        self.description_status = "not_run"
        self.discovery_truncated = False
        self.description_truncated = False
        self.description_bytes = 0
        self.scpd_results: list[dict] = []
        self.scpd_status = "not_run"
        self.scpd_truncated = False
        self.scpd_bytes = 0
        self.scpd_fetches = 0
        self.igd_results: list[dict] = []
        self.port_mapping_results: list[dict] = []
        self.igd_status = "not_run"
        self.port_mapping_status = "not_run"
        self.igd_truncated = False
        self.port_mapping_truncated = False
        self.soap_bytes = 0
        self.soap_budget_exhausted = False

    def _error(self, test: str, error: Exception | str, **details) -> None:
        self.module_errors.append({"test": test, "error": str(error)[:300], **details})

    def discover(self) -> list[dict]:
        if self.discovery_status != "not_run":
            return self.discoveries
        multicast = bool(getattr(self.args, "multicast", False))
        if multicast:
            payload = build_multicast_msearch(self.args.search_target, self.args.mx)
            destination = (MULTICAST_ADDRESS, MULTICAST_PORT)
            interface_ip = self.args.interface_ip
        else:
            payload = build_msearch(self.args.search_target, self.target_ip, self.port)
            destination = (self.target_ip, self.port)
            interface_ip = "0.0.0.0"
        seen: set[tuple] = set()
        received = 0
        max_responses = int(self.args.max_responses)
        receive_limit = MAX_MULTICAST_DATAGRAMS if multicast else max_responses * 4
        timeout = float(self.args.timeout_seconds)
        if multicast:
            timeout = max(timeout, float(self.args.mx))
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((interface_ip, 0))
                if multicast:
                    sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(interface_ip),
                    )
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.args.ttl)
                sock.sendto(payload, destination)
                deadline = time.monotonic() + timeout
                while len(self.discoveries) < max_responses and received < receive_limit:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        packet, source = sock.recvfrom(MAX_DATAGRAM_BYTES + 1)
                    except TimeoutError:
                        break
                    received += 1
                    if multicast and source[0] != self.target_ip:
                        continue
                    response = parse_ssdp_response(packet, source)
                    if response["sourceIp"] != self.target_ip:
                        response["validationErrors"].append("unexpected_source")
                        response["valid"] = False
                    requested = self.args.search_target
                    if requested != "ssdp:all" and response["st"] != requested:
                        response["validationErrors"].append("st_mismatch")
                        response["valid"] = False
                    key = (
                        response["sourceIp"], response["st"], response["usn"],
                        response["location"],
                    )
                    if key not in seen:
                        seen.add(key)
                        self.discoveries.append(response)
                self.discovery_truncated = (
                    len(self.discoveries) >= max_responses or received >= receive_limit
                )
        except OSError as exc:
            self._error("DISCOVER", exc)
            self.discovery_status = "partial" if self.discoveries else "error"
            return self.discoveries
        if self.discovery_truncated or any(not item["valid"] for item in self.discoveries):
            self.discovery_status = "partial"
        elif self.discoveries:
            self.discovery_status = "complete"
        else:
            self.discovery_status = "no_response"
        return self.discoveries

    def _description_url(self, location: str):
        if len(location) > MAX_LOCATION_LENGTH:
            raise OutOfScopeLocation("LOCATION exceeds URL length limit")
        try:
            parsed = urlsplit(location)
            if parsed.scheme.lower() not in ("http", "https"):
                raise OutOfScopeLocation("LOCATION must use HTTP or HTTPS")
            host = parsed.hostname
            if (
                not host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise OutOfScopeLocation("LOCATION has an invalid authority or fragment")
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme.lower() == "https" else 80
            if not 1 <= port <= 65535:
                raise OutOfScopeLocation("LOCATION has an invalid port")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                try:
                    resolved = {
                        item[4][0]
                        for item in socket.getaddrinfo(
                            host, port, socket.AF_INET, socket.SOCK_STREAM
                        )
                    }
                except socket.gaierror as exc:
                    raise OutOfScopeLocation("LOCATION hostname cannot be resolved") from exc
                if self.target_ip not in resolved:
                    raise OutOfScopeLocation("LOCATION hostname is outside the selected target")
            else:
                if address.version != 4 or str(address) != self.target_ip:
                    raise OutOfScopeLocation("LOCATION IP is outside the selected target")
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            return parsed.scheme.lower(), host, port, path, parsed.netloc
        except ValueError as exc:
            if isinstance(exc, OutOfScopeLocation):
                raise
            raise OutOfScopeLocation(f"invalid LOCATION: {exc}") from exc

    def _request_target(
        self,
        url: str,
        method: str,
        *,
        headers: dict[str, str],
        max_bytes: int,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        """Issue one bounded HTTP request pinned to the selected device IP."""
        scheme, host, port, path, authority = self._description_url(url)
        timeout = float(self.args.timeout_seconds)
        if scheme == "https":
            connection = _PinnedHTTPSConnection(host, self.target_ip, port, timeout)
        else:
            connection = http.client.HTTPConnection(self.target_ip, port, timeout=timeout)
        expired = threading.Event()

        def end_request() -> None:
            expired.set()
            sock = connection.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()

        deadline = threading.Timer(timeout, end_request)
        deadline.daemon = True
        deadline.start()
        try:
            request_headers = {"Host": authority, **headers}
            connection.request(
                method, path, body=body, headers=request_headers,
            )
            response = connection.getresponse()
            encoding = (response.getheader("Content-Encoding") or "identity").lower()
            if encoding != "identity":
                raise ValueError(f"unsupported Content-Encoding: {encoding}")
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    declared_length = int(length)
                except ValueError as exc:
                    raise ValueError("invalid Content-Length") from exc
                if declared_length < 0:
                    raise ValueError("invalid Content-Length")
                if declared_length > max_bytes:
                    raise ResponseSizeExceeded()
            response_body = response.read(max_bytes + 1)
            if expired.is_set():
                raise TimeoutError("HTTP request exceeded total timeout")
            if len(response_body) > max_bytes:
                raise ResponseSizeExceeded(len(response_body))
            return response.status, response_body
        finally:
            deadline.cancel()
            connection.close()

    def _fetch_description(self, location: str) -> bytes:
        remaining = MAX_TOTAL_DESCRIPTION_BYTES - self.description_bytes
        if remaining <= 0:
            raise ValueError("description byte budget reached")
        try:
            status, body = self._request_target(
                location,
                "GET",
                headers={"Accept": "text/xml, application/xml"},
                max_bytes=min(int(self.args.max_description_bytes), remaining),
            )
        except ResponseSizeExceeded as exc:
            self.description_bytes += exc.read_bytes
            raise
        self.description_bytes += len(body)
        if status != 200:
            raise ValueError(f"description returned HTTP {status}")
        return body

    def describe(self) -> list[dict]:
        if self.description_status != "not_run":
            return self.devices
        if self.discovery_status == "not_run":
            self.discover()
        locations: dict[str, list[dict]] = {}
        for discovery in self.discoveries:
            if discovery["valid"] and discovery["location"]:
                locations.setdefault(discovery["location"], []).append(discovery)
        fetched = 0
        for location, adverts in locations.items():
            item = {
                "location": location,
                "advertisedUsns": list(dict.fromkeys(a["usn"] for a in adverts)),
                "status": "error",
            }
            if fetched >= MAX_DESCRIPTION_FETCHES or self.description_bytes >= MAX_TOTAL_DESCRIPTION_BYTES:
                item["status"] = "skipped"
                item["error"] = "description_count_or_total_size_limit_reached"
                self.description_truncated = True
                self.devices.append(item)
                continue
            try:
                fetched += 1
                xml_bytes = self._fetch_description(location)
                if self.description_bytes > MAX_TOTAL_DESCRIPTION_BYTES:
                    item["status"] = "skipped"
                    item["error"] = "total_description_size_limit_reached"
                    self.description_truncated = True
                    self.devices.append(item)
                    continue
                description = parse_device_description(xml_bytes, location)
                item["description"] = description
                item["status"] = "described"
                known_udns = _all_udns(description["device"])
                item["identityMatch"] = all(
                    usn.split("::", 1)[0].lower() in known_udns
                    for usn in item["advertisedUsns"]
                )
            except OutOfScopeLocation as exc:
                item["status"] = "skipped"
                item["error"] = str(exc)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                item["error"] = str(exc)[:300]
                self._error("DESCRIBE", exc, location=location)
            self.devices.append(item)
        described = sum(item["status"] == "described" for item in self.devices)
        if not self.devices:
            self.description_status = "no_devices"
        elif described == len(self.devices):
            self.description_status = "complete"
        elif described:
            self.description_status = "partial"
        else:
            self.description_status = "error" if self.module_errors else "partial"
        return self.devices

    def _igd_services(self) -> list[dict]:
        if self.description_status == "not_run":
            self.describe()
        found: list[dict] = []
        seen: set[tuple] = set()
        for item in self.devices:
            if item["status"] != "described":
                continue
            pending = [item["description"]["device"]]
            while pending:
                device = pending.pop()
                udn = device["udn"]
                for service in device["services"]:
                    service_type = service["serviceType"]
                    if service_type not in SUPPORTED_SERVICE_TYPES:
                        continue
                    control_url = service["controlUrl"]
                    key = (udn, service_type, control_url)
                    if key not in seen:
                        seen.add(key)
                        found.append({
                            "udn": udn,
                            "serviceType": service_type,
                            "controlUrl": control_url,
                        })
                        if len(found) > MAX_IGD_SERVICE_CANDIDATES:
                            return found
                pending.extend(reversed(device["embeddedDevices"]))
        return found

    def _scpd_services(self) -> list[dict]:
        if self.description_status == "not_run":
            self.describe()
        found: list[dict] = []
        seen: set[tuple] = set()
        for item in self.devices:
            if item["status"] != "described":
                continue
            pending = [item["description"]["device"]]
            while pending:
                device = pending.pop()
                for service in device["services"]:
                    reference = {
                        "udn": device["udn"],
                        "serviceType": service["serviceType"],
                        "scpdUrl": service["scpdUrl"],
                    }
                    key = tuple(reference.values())
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(reference)
                    if len(found) > MAX_SCPD_SERVICE_CANDIDATES:
                        return found
                pending.extend(reversed(device["embeddedDevices"]))
        return found

    def scpd(self) -> list[dict]:
        """Fetch selected-target service descriptions under request and byte budgets."""
        if self.scpd_status != "not_run":
            return self.scpd_results
        max_fetches = min(max(1, int(getattr(self.args, "max_scpd", 20))), 100)
        for position, service in enumerate(self._scpd_services()):
            result = {**service, "status": "skipped"}
            url = service["scpdUrl"]
            if position >= MAX_SCPD_SERVICE_CANDIDATES:
                result["error"] = "service_candidate_limit_reached"
                self.scpd_truncated = True
                self.scpd_results.append(result)
                break
            if not url:
                result["error"] = "missing_scpd_url"
                self.scpd_results.append(result)
                continue
            try:
                self._description_url(url)
            except OutOfScopeLocation as exc:
                result["error"] = str(exc)
                self.scpd_results.append(result)
                continue
            if self.scpd_fetches >= max_fetches or self.scpd_bytes >= MAX_TOTAL_SCPD_BYTES:
                result["error"] = "scpd_fetch_or_byte_limit_reached"
                self.scpd_truncated = True
                self.scpd_results.append(result)
                break
            try:
                self.scpd_fetches += 1
                try:
                    status, body = self._request_target(
                        url, "GET",
                        headers={"Accept": "text/xml, application/xml"},
                        max_bytes=min(
                            MAX_SCPD_BYTES, MAX_TOTAL_SCPD_BYTES - self.scpd_bytes
                        ),
                    )
                except ResponseSizeExceeded as exc:
                    self.scpd_bytes += exc.read_bytes
                    if self.scpd_bytes >= MAX_TOTAL_SCPD_BYTES:
                        self.scpd_truncated = True
                    raise
                self.scpd_bytes += len(body)
                if self.scpd_bytes > MAX_TOTAL_SCPD_BYTES:
                    result["error"] = "scpd_byte_limit_reached"
                    self.scpd_truncated = True
                    self.scpd_results.append(result)
                    break
                if status in (401, 403):
                    result["status"] = "denied"
                    result["httpStatus"] = status
                elif status != 200:
                    raise ValueError(f"service description returned HTTP {status}")
                else:
                    result["description"] = parse_service_description(body)
                    result["status"] = "described"
            except (OSError, ValueError, http.client.HTTPException) as exc:
                result["status"] = "error"
                result["error"] = str(exc)[:300]
                self._error("SCPD", exc, scpdUrl=url)
            self.scpd_results.append(result)
        if not self.scpd_results:
            self.scpd_status = (
                "no_services" if self.description_status == "complete" else "inconclusive"
            )
        elif all(item["status"] == "described" for item in self.scpd_results):
            self.scpd_status = "complete"
        elif all(item["status"] == "error" for item in self.scpd_results):
            self.scpd_status = "error"
        else:
            self.scpd_status = "partial"
        return self.scpd_results

    def _soap_request(
        self,
        service_type: str,
        control_url: str,
        action: str,
        arguments: dict[str, str | int],
    ) -> dict[str, str]:
        if self.soap_budget_exhausted or self.soap_bytes >= MAX_TOTAL_SOAP_BYTES:
            self.soap_budget_exhausted = True
            raise SoapBudgetExceeded("SOAP response byte budget reached")
        payload = build_soap_request(service_type, action, arguments)
        try:
            status, response = self._request_target(
                control_url,
                "POST",
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPACTION": f'"{service_type}#{action}"',
                    "Accept": "text/xml, application/xml",
                },
                max_bytes=min(MAX_SOAP_BYTES, MAX_TOTAL_SOAP_BYTES - self.soap_bytes),
                body=payload,
            )
        except ResponseSizeExceeded as exc:
            self.soap_bytes += exc.read_bytes
            if self.soap_bytes >= MAX_TOTAL_SOAP_BYTES:
                self.soap_budget_exhausted = True
            raise
        self.soap_bytes += len(response)
        if self.soap_bytes > MAX_TOTAL_SOAP_BYTES:
            self.soap_budget_exhausted = True
            raise SoapBudgetExceeded("SOAP response byte budget reached")
        if status in (401, 403):
            raise HttpAccessDenied(status)
        if status not in (200, 500):
            raise ValueError(f"SOAP request returned HTTP {status}")
        values = parse_soap_response(response, action, service_type)
        if status != 200:
            raise ValueError("SOAP success response used HTTP 500")
        return values

    @staticmethod
    def _overall_igd_status(results: list[dict]) -> str:
        if not results:
            return "no_services"
        if all(item["status"] == "complete" for item in results):
            return "complete"
        if all(item["status"] == "error" for item in results):
            return "error"
        return "partial"

    def igd_info(self) -> list[dict]:
        if self.igd_status != "not_run":
            return self.igd_results
        eligible = 0
        for position, service in enumerate(self._igd_services()):
            result = {**service, "status": "skipped", "actions": {}}
            control_url = service["controlUrl"]
            if position >= MAX_IGD_SERVICE_CANDIDATES:
                result["error"] = "service_candidate_limit_reached"
                self.igd_truncated = True
                self.igd_results.append(result)
                break
            if self.soap_budget_exhausted:
                result["error"] = "soap_byte_budget_reached"
                self.igd_truncated = True
                self.igd_results.append(result)
                continue
            if not control_url:
                result["error"] = "missing_control_url"
                self.igd_results.append(result)
                continue
            try:
                self._description_url(control_url)
            except OutOfScopeLocation as exc:
                result["error"] = str(exc)
                self.igd_results.append(result)
                continue
            if eligible >= MAX_IGD_SERVICES:
                result["error"] = "service_limit_reached"
                self.igd_truncated = True
                self.igd_results.append(result)
                break
            eligible += 1
            for action in IGD_INFO_ACTIONS:
                try:
                    values = self._soap_request(
                        service["serviceType"], control_url, action, {}
                    )
                    result["actions"][action] = {"status": "ok", "values": values}
                except SoapFault as exc:
                    kind = (
                        "unsupported" if exc.code in (401, 602)
                        else "denied" if exc.code == 606
                        else "fault"
                    )
                    result["actions"][action] = {
                        "status": kind,
                        "errorCode": exc.code,
                        "error": exc.description,
                    }
                except HttpAccessDenied as exc:
                    result["actions"][action] = {
                        "status": "denied", "httpStatus": exc.status,
                    }
                except SoapBudgetExceeded:
                    result["actions"][action] = {
                        "status": "skipped", "error": "soap_byte_budget_reached",
                    }
                    self.igd_truncated = True
                    break
                except (OSError, ValueError, http.client.HTTPException) as exc:
                    result["actions"][action] = {
                        "status": "error", "error": str(exc)[:300],
                    }
                    self._error(
                        "IGDINFO", exc,
                        serviceType=service["serviceType"], action=action,
                    )
            action_states = [entry["status"] for entry in result["actions"].values()]
            if self.soap_budget_exhausted:
                result["status"] = "partial" if "ok" in action_states else "skipped"
            elif all(state == "ok" for state in action_states):
                result["status"] = "complete"
            elif "ok" in action_states:
                result["status"] = "partial"
            elif all(state == "error" for state in action_states):
                result["status"] = "error"
            else:
                result["status"] = "partial"
            self.igd_results.append(result)
        self.igd_status = self._overall_igd_status(self.igd_results)
        if self.igd_status == "no_services" and self.description_status != "complete":
            self.igd_status = "inconclusive"
        return self.igd_results

    def port_mappings(self) -> list[dict]:
        if self.port_mapping_status != "not_run":
            return self.port_mapping_results
        remaining = min(max(1, int(getattr(self.args, "max_mappings", 100))), 1000)
        eligible = 0
        for position, service in enumerate(self._igd_services()):
            result = {**service, "status": "skipped", "entries": [], "truncated": False}
            control_url = service["controlUrl"]
            if position >= MAX_IGD_SERVICE_CANDIDATES:
                result["error"] = "service_candidate_limit_reached"
                result["truncated"] = True
                self.port_mapping_truncated = True
                self.port_mapping_results.append(result)
                break
            if remaining == 0:
                result["error"] = "service_or_mapping_limit_reached"
                result["truncated"] = True
                self.port_mapping_truncated = True
                self.port_mapping_results.append(result)
                continue
            if self.soap_budget_exhausted:
                result["error"] = "soap_byte_budget_reached"
                result["truncated"] = True
                self.port_mapping_truncated = True
                self.port_mapping_results.append(result)
                continue
            if not control_url:
                result["error"] = "missing_control_url"
                self.port_mapping_results.append(result)
                continue
            try:
                self._description_url(control_url)
            except OutOfScopeLocation as exc:
                result["error"] = str(exc)
                self.port_mapping_results.append(result)
                continue
            if eligible >= MAX_IGD_SERVICES:
                result["error"] = "service_limit_reached"
                result["truncated"] = True
                self.port_mapping_truncated = True
                self.port_mapping_results.append(result)
                break
            eligible += 1
            index = 0
            while remaining:
                try:
                    values = self._soap_request(
                        service["serviceType"], control_url,
                        "GetGenericPortMappingEntry",
                        {"NewPortMappingIndex": index},
                    )
                    result["entries"].append({"index": index, **values})
                    index += 1
                    remaining -= 1
                except SoapFault as exc:
                    if exc.code == 713:
                        result["status"] = "complete"
                    else:
                        result["status"] = "partial"
                        result["errorCode"] = exc.code
                        result["error"] = exc.description
                    break
                except HttpAccessDenied as exc:
                    result["status"] = "partial"
                    result["httpStatus"] = exc.status
                    break
                except SoapBudgetExceeded:
                    result["status"] = "partial" if result["entries"] else "skipped"
                    result["error"] = "soap_byte_budget_reached"
                    result["truncated"] = True
                    self.port_mapping_truncated = True
                    break
                except (OSError, ValueError, http.client.HTTPException) as exc:
                    result["status"] = "partial" if result["entries"] else "error"
                    result["error"] = str(exc)[:300]
                    self._error(
                        "PORTMAPS", exc,
                        serviceType=service["serviceType"], index=index,
                    )
                    break
            else:
                result["status"] = "partial"
                result["truncated"] = True
                self.port_mapping_truncated = True
            self.port_mapping_results.append(result)
        self.port_mapping_status = self._overall_igd_status(self.port_mapping_results)
        if self.port_mapping_status == "no_services" and self.description_status != "complete":
            self.port_mapping_status = "inconclusive"
        return self.port_mapping_results

    def output(self) -> None:
        properties = {
            "software_type": None,
            "name": "upnp",
            "version": None,
            "vendor": None,
            "description": None,
            "target": self.target_host,
            "targetIp": self.target_ip,
            "udpPort": self.port,
            "discoveryStatus": self.discovery_status,
            "descriptionStatus": self.description_status,
            "discoveryTruncated": self.discovery_truncated,
            "descriptionTruncated": self.description_truncated,
            "descriptionBytes": self.description_bytes,
            "scpdStatus": self.scpd_status,
            "scpdTruncated": self.scpd_truncated,
            "scpdBytes": self.scpd_bytes,
            "scpdFetches": self.scpd_fetches,
            "serviceDescriptions": self.scpd_results,
            "soapBytes": self.soap_bytes,
            "soapByteLimit": MAX_TOTAL_SOAP_BYTES,
            "soapTruncated": self.soap_budget_exhausted,
            "igdInfoStatus": self.igd_status,
            "igdInfoTruncated": self.igd_truncated,
            "igdInfo": self.igd_results,
            "portMappingStatus": self.port_mapping_status,
            "portMappingTruncated": self.port_mapping_truncated,
            "portMappings": self.port_mapping_results,
            "discoveries": self.discoveries,
            "devices": self.devices,
        }
        if self.module_errors:
            properties["moduleErrors"] = self.module_errors
        output_path = getattr(self.args, "output", None)
        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as stream:
                    json.dump(properties, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
            except OSError as exc:
                self._error("OUTPUT", exc)
                properties["moduleErrors"] = self.module_errors
        node = self.ptjsonlib.create_node_object("software", None, None, properties)
        self.ptjsonlib.add_node(node)
        if self.module_errors:
            self.ptjsonlib.set_status("error", "UPnP module failure")
        else:
            self.ptjsonlib.set_status("finished", "")
        if getattr(self.args, "json", False):
            print(self.ptjsonlib.get_result_json())
