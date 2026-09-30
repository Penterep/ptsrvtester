"""Bounded receiver for target-scoped UPnP GENA unicast events.

The callback is opened before SUBSCRIBE and accepts an initial NOTIFY that may
arrive before the subscription response exposes its SID. This module never
contacts a device or follows URLs. Wire format follows UPnP Device Architecture
2.0, sections 4.1 and 4.3.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import sys
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from typing import Self
from xml.parsers import expat

EVENT_NS = "urn:schemas-upnp-org:event-1-0"
MAX_EVENT_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 1000
MAX_EVENT_ELEMENTS = 300
MAX_EVENT_DEPTH = 16
MAX_EVENT_VARIABLES = 64
MAX_HEADER_BYTES = 16 * 1024
MAX_REQUESTS = 2000
MAX_CONCURRENT_CONNECTIONS = 8
REQUEST_DEADLINE_SECONDS = 3.0
_SID = re.compile(r"uuid:[A-Za-z0-9-]{1,128}\Z")
_SEQ = re.compile(r"[0-9]{1,20}\Z")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,8}\Z")


def _unicast_ip(value: str, name: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or "%" in value:
        raise ValueError(f"{name} must be a unicast IP address without a zone suffix")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"{name} must be a unicast IP address") from None
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise ValueError(f"{name} must be a unicast IP address")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ValueError(f"{name} must not be an IPv4-mapped IPv6 address")
    return address


def _scope_id(value: int, address: ipaddress.IPv4Address | ipaddress.IPv6Address, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**32 - 1:
        raise ValueError(f"{name} must be a nonnegative 32-bit interface index")
    if isinstance(address, ipaddress.IPv4Address):
        if value != 0:
            raise ValueError(f"{name} must be zero for IPv4")
    elif address.is_link_local:
        if value == 0:
            raise ValueError(f"{name} is required for link-local IPv6")
    elif value != 0:
        raise ValueError(f"{name} must be zero for non-link-local IPv6")
    return value


def parse_event_xml(xml_bytes: bytes) -> dict[str, str]:
    """Parse one event propertyset; reject malformed or over-limit XML.

    State-variable names and values are returned without performing schema
    lookup. The caller may compare them with a separately fetched SCPD.
    """
    if not isinstance(xml_bytes, bytes) or not xml_bytes or len(xml_bytes) > MAX_EVENT_BYTES:
        raise ValueError("GENA event XML is empty or exceeds size limit")
    try:
        xml_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("GENA event XML must be UTF-8") from exc

    guard = expat.ParserCreate()
    elements = 0
    depth = 0

    def reject_declaration(*_args):
        raise ValueError("DTD and entity declarations are not allowed in GENA XML")

    def start_element(_name, _attrs):
        nonlocal elements, depth
        elements += 1
        depth += 1
        if elements > MAX_EVENT_ELEMENTS or depth > MAX_EVENT_DEPTH:
            raise ValueError("GENA XML structure exceeds limits")

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
        root = ET.fromstring(xml_bytes)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError(f"invalid GENA XML: {exc}") from exc

    if root.tag != f"{{{EVENT_NS}}}propertyset":
        raise ValueError("GENA XML root is not an event propertyset")
    values: dict[str, str] = {}
    for prop in root:
        if prop.tag != f"{{{EVENT_NS}}}property":
            continue  # Unknown vendor extension.
        variables = [child for child in prop if isinstance(child.tag, str) and not child.tag.startswith("{")]
        if len(variables) != 1:
            raise ValueError("GENA property must contain one unqualified state variable")
        variable = variables[0]
        if len(variable):
            raise ValueError("GENA state variable must contain text only")
        name = variable.tag
        if name in values:
            raise ValueError("GENA propertyset repeats a state variable")
        if len(values) >= MAX_EVENT_VARIABLES:
            raise ValueError("GENA propertyset has too many state variables")
        values[name] = variable.text or ""
    if not values:
        raise ValueError("GENA propertyset has no state variables")
    return values


class _CallbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, owner: GenaCallbackServer):
        self.owner = owner
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Condition()
        self.address_family = owner.address_family
        bind_address = (
            (owner.local_ip, 0, 0, owner.local_scope_id)
            if owner.address_family == socket.AF_INET6 else (owner.local_ip, 0)
        )
        super().__init__(bind_address, _CallbackHandler)

    def server_bind(self) -> None:
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        TCPServer.server_bind(self)  # Avoid HTTPServer's reverse-DNS lookup on the local IP.
        self.server_name = self.owner.local_ip
        self.server_port = self.server_address[1]

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2.0)
        return connection, address

    @staticmethod
    def _abort(connection: socket.socket) -> None:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()

    def process_request(self, request: socket.socket, client_address: tuple) -> None:
        if not self._slots.acquire(blocking=False):
            self._abort(request)
            return
        with self._active_lock:
            self._active.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active.discard(request)
                self._active_lock.notify_all()
            self._slots.release()
            self._abort(request)
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple) -> None:
        deadline = threading.Timer(REQUEST_DEADLINE_SECONDS, self._abort, args=(request,))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            with self._active_lock:
                self._active.discard(request)
                self._active_lock.notify_all()
            self._slots.release()

    def close_active(self) -> None:
        with self._active_lock:
            connections = tuple(self._active)
        for connection in connections:
            self._abort(connection)

    def wait_closed(self, seconds: float) -> bool:
        with self._active_lock:
            return self._active_lock.wait_for(lambda: not self._active, timeout=seconds)

    def handle_error(self, request: socket.socket, client_address: tuple) -> None:
        if isinstance(sys.exc_info()[1], OSError) and request.fileno() < 0:
            return  # Expected when the absolute deadline or stop closes a sender.
        super().handle_error(request, client_address)


class _CallbackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _CallbackHTTPServer

    def log_message(self, _format, *_args):
        pass

    def _reply(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _single_header(self, name: str) -> str | None:
        values = self.headers.get_all(name, [])
        return values[0].strip() if len(values) == 1 else None

    def _discard_bounded_body(self) -> None:
        """Avoid resetting a valid small sender when rejecting on a reached cap."""
        length = self._single_header("Content-Length")
        if length and re.fullmatch(r"[0-9]{1,10}", length) and int(length) <= MAX_EVENT_BYTES:
            self.connection.settimeout(0.2)
            try:
                self.rfile.read(int(length))
            except (OSError, TimeoutError):
                pass

    def _reject(self, status: int) -> None:
        self._discard_bounded_body()
        self._reply(status)

    def _read_chunked(self, limit: int) -> bytes:
        parts = bytearray()
        chunks = 0
        while True:
            line = self.rfile.readline(65)
            if not line.endswith(b"\r\n") or len(line) > 64:
                raise ValueError("malformed chunk size")
            size_text = line[:-2].split(b";", 1)[0].strip()
            if not _CHUNK_SIZE.fullmatch(size_text):
                raise ValueError("malformed chunk size")
            size = int(size_text, 16)
            if size > limit - len(parts):
                raise OverflowError("GENA event exceeds byte limit")
            if size == 0:
                for _ in range(16):
                    trailer = self.rfile.readline(1025)
                    if trailer == b"\r\n":
                        return bytes(parts)
                    if not trailer.endswith(b"\r\n") or len(trailer) > 1024:
                        raise ValueError("malformed chunk trailer")
                raise ValueError("too many chunk trailers")
            chunks += 1
            if chunks > 1024:
                raise ValueError("too many chunks")
            data = self.rfile.read(size)
            if len(data) != size or self.rfile.read(2) != b"\r\n":
                raise ValueError("truncated chunk")
            parts.extend(data)

    def _body(self, limit: int) -> bytes:
        if len(self.headers.get_all("Transfer-Encoding", [])) > 1:
            raise ValueError("duplicate transfer encoding")
        if len(self.headers.get_all("Content-Length", [])) > 1:
            raise ValueError("duplicate content length")
        transfer = self._single_header("Transfer-Encoding")
        length = self._single_header("Content-Length")
        if transfer is not None:
            if length is not None or transfer.lower() != "chunked" or self.request_version != "HTTP/1.1":
                raise ValueError("unsupported transfer encoding")
            return self._read_chunked(limit)
        if length is None or not re.fullmatch(r"[0-9]{1,10}", length):
            raise ValueError("missing or invalid content length")
        size = int(length)
        if size > limit:
            raise OverflowError("GENA event exceeds byte limit")
        data = self.rfile.read(size)
        if len(data) != size:
            raise ValueError("truncated GENA event")
        return data

    def do_NOTIFY(self) -> None:
        owner = self.server.owner
        self.connection.settimeout(2.0)
        if not owner._source_matches(self.client_address):
            self._reject(403)
            return
        if self.path != owner.path:
            self._reject(404)
            return
        with owner._condition:
            if owner._closed:
                self._reject(503)
                return
            owner._requests += 1
            if owner._requests > MAX_REQUESTS or len(owner._events) + len(owner._provisional) >= owner.max_events:
                owner._truncated = True
                owner._condition.notify_all()
                self._reject(429)
                return
        if len(self.headers) > 64 or sum(len(key) + len(value) for key, value in self.headers.items()) > MAX_HEADER_BYTES:
            self._reject(431)
            return
        if self._single_header("Host") != f"{owner._authority}:{owner.port}":
            self._reject(400)
            return
        content_type = self._single_header("Content-Type")
        if not content_type or not re.fullmatch(
            r'text/xml\s*;\s*charset\s*=\s*"?utf-8"?', content_type, re.IGNORECASE
        ):
            self._reject(400)
            return
        nt = self._single_header("NT")
        nts = self._single_header("NTS")
        sid = self._single_header("SID")
        sequence = self._single_header("SEQ")
        if nt != "upnp:event" or nts != "upnp:propchange" or not sid or not _SID.fullmatch(sid):
            self._reject(412)
            return
        if sequence is None or not _SEQ.fullmatch(sequence) or int(sequence) > 2**32 - 1:
            self._reject(400)
            return
        with owner._condition:
            if owner._sid is not None and sid != owner._sid:
                self._reject(412)
                return
        with owner._body_lock:
            with owner._condition:
                remaining = min(MAX_EVENT_BYTES, owner.max_total_bytes - owner._total_bytes)
            if remaining <= 0:
                with owner._condition:
                    owner._truncated = True
                    owner._condition.notify_all()
                self._reject(413)
                return
            try:
                body = self._body(remaining)
            except OverflowError:
                with owner._condition:
                    owner._truncated = True
                    owner._condition.notify_all()
                self._reply(413)
                return
            except (ValueError, TimeoutError):
                self._reply(400)
                return
            with owner._condition:
                if owner._closed:
                    self._reply(503)
                    return
                owner._total_bytes += len(body)
                if owner._total_bytes >= owner.max_total_bytes:
                    owner._truncated = True
                owner._condition.notify_all()
        try:
            properties = parse_event_xml(body)
        except ValueError:
            self._reply(400)
            return
        event = {
            "sid": sid,
            "seq": int(sequence),
            "properties": properties,
            "sourceIp": self.client_address[0],
            "bodyBytes": len(body),
        }
        with owner._condition:
            if owner._closed:
                self._reply(503)
                return
            if len(owner._events) + len(owner._provisional) >= owner.max_events:
                owner._truncated = True
                owner._condition.notify_all()
                self._reply(429)
                return
            if owner._sid is None:
                owner._provisional.append(event)
            elif sid == owner._sid:
                owner._events.append(event)
                owner._condition.notify_all()
            else:
                self._reply(412)
                return
            if len(owner._events) + len(owner._provisional) >= owner.max_events:
                owner._truncated = True
                owner._condition.notify_all()
        self._reply(200)

    def do_GET(self) -> None:
        self._reply(405)

    def do_POST(self) -> None:
        self._reply(405)


class GenaCallbackServer:
    """Short-lived IPv4/IPv6 HTTP callback for one selected UPnP target.

    Start before SUBSCRIBE, call ``set_sid`` on its response, then ``wait``.
    Always call ``stop`` (or use a context manager) even if SUBSCRIBE fails.
    """

    def __init__(
        self,
        target_ip: str,
        local_ip: str,
        max_events: int = 100,
        max_total_bytes: int = MAX_TOTAL_BYTES,
        target_scope_id: int = 0,
        local_scope_id: int = 0,
    ) -> None:
        target_address = _unicast_ip(target_ip, "target_ip")
        local_address = _unicast_ip(local_ip, "local_ip")
        if target_address.version != local_address.version:
            raise ValueError("target_ip and local_ip must use the same address family")
        self.target_ip = str(target_address)
        self.local_ip = str(local_address)
        self._target_address = target_address
        self.address_family = socket.AF_INET6 if target_address.version == 6 else socket.AF_INET
        self.target_scope_id = _scope_id(target_scope_id, target_address, "target_scope_id")
        self.local_scope_id = _scope_id(local_scope_id, local_address, "local_scope_id")
        if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= MAX_EVENTS:
            raise ValueError("max_events must be between 1 and 1000")
        if (
            isinstance(max_total_bytes, bool)
            or not isinstance(max_total_bytes, int)
            or not 1 <= max_total_bytes <= MAX_TOTAL_BYTES
        ):
            raise ValueError("max_total_bytes must be between 1 and 8388608")
        self.max_events = max_events
        self.max_total_bytes = max_total_bytes
        self.path = f"/gena/{secrets.token_urlsafe(24)}"
        self._condition = threading.Condition()
        self._body_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._sid: str | None = None
        self._events: list[dict] = []
        self._provisional: list[dict] = []
        self._total_bytes = 0
        self._requests = 0
        self._truncated = False
        self._closed = False
        self._ever_started = False
        self._server: _CallbackHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def _authority(self) -> str:
        return f"[{self.local_ip}]" if self.address_family == socket.AF_INET6 else self.local_ip

    def _source_matches(self, source: tuple) -> bool:
        if self.address_family == socket.AF_INET:
            return source[0] == self.target_ip
        try:
            address = ipaddress.IPv6Address(str(source[0]).split("%", 1)[0])
        except ValueError:
            return False
        if address != self._target_address:
            return False
        return not self._target_address.is_link_local or (
            len(source) >= 4 and source[3] == self.target_scope_id
        )

    @property
    def port(self) -> int | None:
        return self._server.server_port if self._server is not None else None

    @property
    def callback_url(self) -> str:
        if self.port is None:
            raise RuntimeError("GENA callback server is not started")
        return f"http://{self._authority}:{self.port}{self.path}"

    @property
    def events(self) -> list[dict]:
        with self._condition:
            return [dict(event, properties=event["properties"].copy()) for event in self._events]

    @property
    def received_bytes(self) -> int:
        with self._condition:
            return self._total_bytes

    @property
    def truncated(self) -> bool:
        with self._condition:
            return self._truncated

    def start(self) -> GenaCallbackServer:
        with self._lifecycle_lock:
            if self._ever_started:
                raise RuntimeError("GENA callback server cannot be restarted")
            server = _CallbackHTTPServer(self)
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
            )
            self._server = server
            self._thread = thread
            try:
                thread.start()
            except Exception:
                self._server = None
                self._thread = None
                server.server_close()
                raise
            self._ever_started = True
        return self

    def set_sid(self, sid: str) -> None:
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            raise ValueError("invalid GENA SID")
        with self._condition:
            if self._sid is not None:
                raise RuntimeError("GENA SID is already set")
            self._sid = sid
            self._events.extend(event for event in self._provisional if event["sid"] == sid)
            self._provisional.clear()
            self._condition.notify_all()

    def wait(self, seconds: float) -> list[dict]:
        """Observe for the full duration unless an event/byte/request cap is reached."""
        if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not 0 <= seconds <= 60:
            raise ValueError("seconds must be between 0 and 60")
        with self._condition:
            self._condition.wait_for(lambda: self._truncated, timeout=seconds)
        return self.events

    def stop(self) -> None:
        with self._lifecycle_lock:
            server = self._server
            thread = self._thread
            if server is None:
                return
            try:
                server.shutdown()
            finally:
                server.close_active()
                server.wait_closed(1.0)
                with self._condition:
                    self._closed = True
                    self._condition.notify_all()
                server.server_close()
                if thread is not None:
                    thread.join(timeout=1.0)
                self._server = None
                self._thread = None

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_args) -> None:
        self.stop()


__all__ = ["MAX_EVENT_BYTES", "MAX_TOTAL_BYTES", "GenaCallbackServer", "parse_event_xml"]
