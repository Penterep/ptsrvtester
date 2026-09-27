"""Exercise inherited Impacket proxy readers without opening connections."""
import unittest
from struct import pack
from unittest.mock import Mock, patch

from impacket.dcerpc.v5.rpch import RPCProxyClientException, RTSHeader
from impacket.http import AUTH_NTLM, HTTPClientSecurityProvider

from ptsrvtester.protocols.msrpc.utils.rpc_proxy import ObservedRPCProxyTransport


PROXY_MODULE = "ptsrvtester.protocols.msrpc.utils.rpc_proxy"


class MemorySocket:
    def __init__(self, data=b"", chunk_size=None):
        self.data = data
        self.chunk_size = chunk_size
        self.reads = []
        self.sent = []
        self.timeout = 5.0
        self.closed = False

    def recv(self, count, *args, **kwargs):
        self.reads.append(count)
        if len(self.reads) > 20000:
            raise AssertionError("Reader did not stop on EOF")
        if self.chunk_size is not None:
            count = min(count, self.chunk_size)
        data, self.data = self.data[:count], self.data[count:]
        return data

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def close(self):
        self.closed = True


class MemoryChannel:
    def __init__(self, sock):
        self.sock = sock
        self.request = Mock()

    def close(self):
        self.sock.close()


def proxy_fixture(data=b"", *, chunk_size=None, chunked=False):
    proxy = ObservedRPCProxyTransport("ncacn_http:[593,RpcProxy=example.test:443]")
    proxy.set_connect_timeout(5.0)
    socket_out = MemorySocket(data, chunk_size)
    socket_in = MemorySocket()
    proxy._RPCProxyClient__channels = {
        "RPC_IN_DATA": MemoryChannel(socket_in),
        "RPC_OUT_DATA": MemoryChannel(socket_out),
    }
    proxy._RPCProxyClient__serverChunked = chunked
    return proxy, socket_in, socket_out


def rpc_packet(stub=b"\x00\x00\x00\x00"):
    return pack("<BBBB4sHHIIHBB", 5, 0, 2, 3, b"\x10\x00\x00\x00",
                24 + len(stub), 0, 1, len(stub), 0, 0, 0) + stub


def http_chunk(data):
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


def tunnel_packets():
    result = []
    for commands in ((2, 120000), (6, 1, 0, 262144, 2, 120000)):
        header = RTSHeader()
        header["NumberOfCommands"] = len(commands) // 2
        header["pduData"] = pack("<" + "I" * len(commands), *commands)
        result.append(header.getData())
    return b"".join(result)


class ProxyReceiveTests(unittest.TestCase):
    def test_channel_eof_sets_error_and_closes_both_connections(self):
        proxy, socket_in, socket_out = proxy_fixture()
        socket_in.data = b"HTTP/1.1 100 Cont"
        channel = proxy._RPCProxyClient__channels["RPC_IN_DATA"]
        proxy._RPCProxyClient__remoteName = "LAB"
        with (
            patch.object(HTTPClientSecurityProvider, "connect", return_value=channel),
            patch.object(HTTPClientSecurityProvider, "get_auth_headers", return_value=({"Authorization": "NTLM offline"}, None)),
            patch.object(HTTPClientSecurityProvider, "get_auth_type", return_value=AUTH_NTLM),
        ):
            with self.assertRaisesRegex(RPCProxyClientException, "connection closed"):
                proxy.create_rpc_in_channel()
        self.assertEqual(proxy.channel_status, {"in": "error", "out": "not_tested"})
        self.assertEqual(len(socket_in.reads), 2)
        self.assertEqual(socket_in.timeout, 5.0)
        proxy.disconnect()
        self.assertTrue(socket_in.closed)
        self.assertTrue(socket_out.closed)

    def test_valid_split_continue_header_is_accepted(self):
        proxy, socket_in, _ = proxy_fixture()
        socket_in.data = b"HTTP/1.1 100 Continue\r\nVia: proxy\r\n\r\n"
        socket_in.chunk_size = 1
        proxy._open_channel("in", lambda: proxy._read_100_continue("RPC_IN_DATA"))
        self.assertEqual(proxy.channel_status["in"], "opened")
        self.assertIsNone(proxy._read_budget)
        self.assertEqual(socket_in.timeout, 5.0)

    def test_localized_401_keeps_denied_status(self):
        proxy, socket_in, _ = proxy_fixture()
        socket_in.data = b"HTTP/1.1 401 Nicht autorisiert\r\n\r\n"
        with self.assertRaises(RPCProxyClientException):
            proxy._open_channel("in", lambda: proxy._read_100_continue("RPC_IN_DATA"))
        self.assertEqual(proxy.channel_status["in"], "denied")

    def test_oversized_unterminated_header_is_bounded(self):
        proxy, socket_in, _ = proxy_fixture()
        proxy.MAX_HEADER_BYTES = 64
        socket_in.data = b"HTTP/1.1 100 Continue\r\nX:" + b"a" * 1000
        with self.assertRaisesRegex(RPCProxyClientException, "limit reached"):
            proxy._read_100_continue("RPC_IN_DATA")
        self.assertEqual(socket_in.reads, [65])

    def test_tunnel_http_eof_is_reported(self):
        proxy, socket_in, socket_out = proxy_fixture(b"HTTP/1.1 200 O")
        with self.assertRaisesRegex(RPCProxyClientException, "connection closed"):
            proxy.create_tunnel()
        self.assertEqual(proxy.tunnel_status, "error")
        self.assertEqual(len(socket_out.reads), 2)
        self.assertEqual(len(socket_in.sent), 1)

    def test_tunnel_rts_eof_is_reported(self):
        proxy, _, _ = proxy_fixture(b"HTTP/1.1 200 OK\r\n\r\n" + tunnel_packets()[:12])
        with self.assertRaisesRegex(RPCProxyClientException, "connection closed"):
            proxy.create_tunnel()
        self.assertEqual(proxy.tunnel_status, "error")

    def test_valid_tunnel_with_split_reads_and_optional_http_chunks(self):
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                body = tunnel_packets()
                headers = b"HTTP/1.1 200 OK\r\n"
                if chunked:
                    headers += b"Transfer-Encoding: chunked\r\n"
                    body = http_chunk(body)
                proxy, _, _ = proxy_fixture(headers + b"\r\n" + body, chunk_size=3)
                proxy.create_tunnel()
                self.assertEqual(proxy.tunnel_status, "established")
                self.assertEqual(proxy._RPCProxyClient__serverConnectionTimeout, 120000)
                self.assertEqual(proxy._RPCProxyClient__serverReceiveWindowSize, 262144)

    def test_rpc_eof_in_header_or_body_stops(self):
        packet = rpc_packet()
        for data in (b"", packet[:10], packet[:-1]):
            with self.subTest(length=len(data)):
                proxy, _, socket_out = proxy_fixture(data)
                with self.assertRaisesRegex(RPCProxyClientException, "connection closed"):
                    proxy.recv(count=24)
                self.assertLessEqual(len(socket_out.reads), 2)

    def test_split_rpc_reads_preserve_two_packets(self):
        first, second = rpc_packet(b"abcd"), rpc_packet(b"efgh")
        proxy, _, _ = proxy_fixture(first + second, chunk_size=3)
        self.assertEqual(proxy.recv(count=24), first)
        self.assertEqual(proxy.recv(count=24), second)

    def test_split_chunked_reads_preserve_rpc_packets_and_buffer(self):
        first, second = rpc_packet(b"abcd"), rpc_packet(b"efgh")
        wire = http_chunk(first[:11]) + http_chunk(first[11:] + second)
        proxy, _, _ = proxy_fixture(wire, chunk_size=3, chunked=True)
        self.assertEqual(proxy.recv(count=24), first)
        self.assertEqual(proxy.recv(count=24), second)

    def test_chunked_eof_in_size_data_and_terminating_chunk_stops(self):
        for data in (b"1", b"20\r\nshort", b"0\r\n\r\n"):
            with self.subTest(data=data):
                proxy, _, socket_out = proxy_fixture(data, chunked=True)
                with self.assertRaises(RPCProxyClientException):
                    proxy.recv(count=24)
                self.assertLessEqual(len(socket_out.reads), 2)

    def test_huge_chunk_length_never_requests_unbounded_socket_allocation(self):
        proxy, _, socket_out = proxy_fixture(b"7fffffffffffffff\r\n" + b"a" * 1024, chunk_size=20, chunked=True)
        proxy.MAX_OPERATION_BYTES = 64
        with self.assertRaisesRegex(RPCProxyClientException, "limit reached"):
            proxy.recv(count=24)
        self.assertLessEqual(max(socket_out.reads), 65)

    def test_read_count_bounds_nonterminating_stream(self):
        proxy, socket_in, _ = proxy_fixture()
        proxy.MAX_OPERATION_READS = 4
        socket_in.data = b"a" * 100
        socket_in.chunk_size = 1
        with self.assertRaisesRegex(RPCProxyClientException, "limit reached"):
            proxy._read_100_continue("RPC_IN_DATA")
        self.assertEqual(len(socket_in.reads), 4)

    def test_deadline_does_not_restart_for_each_short_read(self):
        proxy, socket_in, _ = proxy_fixture()
        socket_in.data = b"HTTP/1.1 100 Continue\r\n\r\n"
        socket_in.chunk_size = 1
        with patch(f"{PROXY_MODULE}.monotonic", side_effect=[0.0, 0.0, 6.0]):
            with self.assertRaisesRegex(TimeoutError, "timed out"):
                proxy._read_100_continue("RPC_IN_DATA")
        self.assertEqual(len(socket_in.reads), 1)
        self.assertEqual(socket_in.timeout, 5.0)
        self.assertIsNone(proxy._read_budget)


if __name__ == "__main__":
    unittest.main()
