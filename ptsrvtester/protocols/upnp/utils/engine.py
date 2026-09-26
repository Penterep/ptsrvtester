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

MAX_DATAGRAM_BYTES = 8192
MAX_XML_ELEMENTS = 5000
MAX_XML_NESTING = 64
MAX_DEVICE_DEPTH = 16
MAX_LOCATION_LENGTH = 2048
MAX_DESCRIPTION_FETCHES = 50
MAX_TOTAL_DESCRIPTION_BYTES = 32 * 1024 * 1024
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d+)\s*(?:,|$)", re.IGNORECASE)


class OutOfScopeLocation(ValueError):
    """A device description URL is outside the selected target."""


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

    def _error(self, test: str, error: Exception | str, **details) -> None:
        self.module_errors.append({"test": test, "error": str(error)[:300], **details})

    def discover(self) -> list[dict]:
        if self.discovery_status != "not_run":
            return self.discoveries
        payload = build_msearch(self.args.search_target, self.target_ip, self.port)
        seen: set[tuple] = set()
        received = 0
        max_responses = int(self.args.max_responses)
        timeout = float(self.args.timeout_seconds)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("0.0.0.0", 0))
                sock.sendto(payload, (self.target_ip, self.port))
                deadline = time.monotonic() + timeout
                while len(self.discoveries) < max_responses and received < max_responses * 4:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        packet, source = sock.recvfrom(MAX_DATAGRAM_BYTES + 1)
                    except TimeoutError:
                        break
                    received += 1
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
                    len(self.discoveries) >= max_responses or received >= max_responses * 4
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

    def _fetch_description(self, location: str) -> bytes:
        scheme, host, port, path, authority = self._description_url(location)
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
            connection.request(
                "GET", path,
                headers={"Host": authority, "Accept": "text/xml, application/xml"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError(f"description returned HTTP {response.status}")
            encoding = (response.getheader("Content-Encoding") or "identity").lower()
            if encoding != "identity":
                raise ValueError(f"unsupported Content-Encoding: {encoding}")
            limit = int(self.args.max_description_bytes)
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    if int(length) > limit:
                        raise ValueError("device description exceeds size limit")
                except ValueError as exc:
                    if "exceeds" in str(exc):
                        raise
                    raise ValueError("invalid Content-Length") from exc
            body = response.read(limit + 1)
            if expired.is_set():
                raise TimeoutError("device description request exceeded total timeout")
            if len(body) > limit:
                raise ValueError("device description exceeds size limit")
            return body
        finally:
            deadline.cancel()
            connection.close()

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
                if self.description_bytes + len(xml_bytes) > MAX_TOTAL_DESCRIPTION_BYTES:
                    item["status"] = "skipped"
                    item["error"] = "total_description_size_limit_reached"
                    self.description_truncated = True
                    self.devices.append(item)
                    continue
                description = parse_device_description(xml_bytes, location)
                self.description_bytes += len(xml_bytes)
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
