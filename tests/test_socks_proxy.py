import socket
import struct

from paramiko.py3compat import u
from paramiko.socks_proxy import SocksMessage


class TestSocksMessage:
    AUTH_METHOD_REQUEST = b"\x05\x01\x00"
    CMD_REQUEST_IPV4 = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f@"
    CMD_REQUEST_DOMAIN = b"\x05\x01\x00\x03\tlocalhost\x1f@"
    CMD_REQUEST_IPV6 = b"\x05\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f@"    # noqa

    AUTH_METHOD_RESPONSE = b"\x05\x00"
    CMD_RESPONSE_IPV4 = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f@"
    CMD_RESPONSE_IPV6 = b"\x05\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f@"    # noqa

    LOCALHOST_IPV4 = struct.unpack("!I", socket.inet_aton("127.0.0.1"))[0]
    LOCALHOST_IPV6_HI, LOCALHOST_IPV6_LO = struct.unpack(
        "!QQ",
        socket.inet_pton(socket.AF_INET6, "::1")
    )

    def test_encode(self):
        # auth method selection request
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        assert msg.asbytes() == self.AUTH_METHOD_REQUEST

        # auth method selection response
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(0)
        assert msg.asbytes() == self.AUTH_METHOD_RESPONSE

        # SOCKS CONNECT request for IPv4 destination
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        msg.add_char(1)
        msg.add_int(self.LOCALHOST_IPV4)
        msg.add_short(8000)
        assert msg.asbytes() == self.CMD_REQUEST_IPV4

        # SOCKS response for IPv4 destination
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(0)
        msg.add_char(0)
        msg.add_char(1)
        msg.add_int(self.LOCALHOST_IPV4)
        msg.add_short(8000)
        assert msg.asbytes() == self.CMD_RESPONSE_IPV4

        # SOCKS CONNECT request for domain destination
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        msg.add_char(3)
        msg.add_string("localhost")
        msg.add_short(8000)
        assert msg.asbytes() == self.CMD_REQUEST_DOMAIN

        # SOCKS CONNECT request for IPv6 destination
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        msg.add_char(4)
        msg.add_int64(self.LOCALHOST_IPV6_HI)
        msg.add_int64(self.LOCALHOST_IPV6_LO)
        msg.add_short(8000)
        assert msg.asbytes() == self.CMD_REQUEST_IPV6

        # SOCKS response for IPv6 destination
        msg = SocksMessage()
        msg.add_char(5)
        msg.add_char(0)
        msg.add_char(0)
        msg.add_char(4)
        msg.add_int64(self.LOCALHOST_IPV6_HI)
        msg.add_int64(self.LOCALHOST_IPV6_LO)
        msg.add_short(8000)
        assert msg.asbytes() == self.CMD_RESPONSE_IPV6

    def test_decode(self):
        # auth method selection request
        msg = SocksMessage(self.AUTH_METHOD_REQUEST)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert len(msg.get_remainder()) == 0

        # auth method selection response
        msg = SocksMessage(self.AUTH_METHOD_RESPONSE)
        assert msg.get_char() == 5
        assert msg.get_char() == 0
        assert len(msg.get_remainder()) == 0

        # SOCKS CONNECT request for IPv4 destination
        msg = SocksMessage(self.CMD_REQUEST_IPV4)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_char() == 1
        assert msg.get_int() == self.LOCALHOST_IPV4
        assert msg.get_short() == 8000
        assert len(msg.get_remainder()) == 0

        # SOCKS response for IPv4 destination
        msg = SocksMessage(self.CMD_RESPONSE_IPV4)
        assert msg.get_char() == 5
        assert msg.get_char() == 0
        assert msg.get_char() == 0
        assert msg.get_char() == 1
        assert msg.get_int() == self.LOCALHOST_IPV4
        assert msg.get_short() == 8000
        assert len(msg.get_remainder()) == 0

        # SOCKS CONNECT request for domain destination
        msg = SocksMessage(self.CMD_REQUEST_DOMAIN)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_char() == 3
        assert msg.get_string() == "localhost"
        assert msg.get_short() == 8000
        assert len(msg.get_remainder()) == 0

        # SOCKS CONNECT request for IPv6 destination
        msg = SocksMessage(self.CMD_REQUEST_IPV6)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_char() == 4
        assert msg.get_int64() == self.LOCALHOST_IPV6_HI
        assert msg.get_int64() == self.LOCALHOST_IPV6_LO
        assert msg.get_short() == 8000
        assert len(msg.get_remainder()) == 0

        # SOCKS response for IPv6 destination
        msg = SocksMessage(self.CMD_RESPONSE_IPV6)
        assert msg.get_char() == 5
        assert msg.get_char() == 0
        assert msg.get_char() == 0
        assert msg.get_char() == 4
        assert msg.get_int64() == self.LOCALHOST_IPV6_HI
        assert msg.get_int64() == self.LOCALHOST_IPV6_LO
        assert msg.get_short() == 8000
        assert len(msg.get_remainder()) == 0

    def test_misc(self):
        sample = b"hello"

        msg = SocksMessage()
        msg.add_bytes(sample)
        assert msg.get_so_far() == sample
        msg.rewind()
        assert msg.get_remainder() == sample
        assert u(msg.asbytes()) == str(msg)
        assert repr(msg) == "paramiko.SocksMessage(" + \
               repr(msg.packet.getvalue()) + ")"
