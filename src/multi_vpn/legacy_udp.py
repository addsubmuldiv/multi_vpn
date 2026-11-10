"""Legacy IPv4 UDP data channel with an explicit IV in each datagram."""
import errno
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .operations import check_cancelled, wait_ready
from .native_cbc import native_cbc
from .protocol import legacy_frame
from .wire import validate_ipv4


PREFIX = bytes.fromhex('fefcefbec192a4d6021c0010')
GATEWAY_PREFIX = bytes.fromhex('fefcefbec192a4d6011c')
PROBE = legacy_frame(14)
PROBE_ID_OFFSET = 32
PATH_MTU_STEPS = (1360, 1320, 1280, 1200, 1000, 576)
MIN_RECEIVE_BUFFER = 256 * 1024


class LegacyUdp:
    def __init__(self, key, user_id, vip, gateway):
        self.algorithm = algorithms.AES128(key)
        self.native = None
        try:
            self.native = native_cbc(key)
        except (OSError, AttributeError):
            pass
        self.user_id = struct.pack('!I', user_id)
        self.endpoint = None
        self.probe_header = bytes.fromhex('458000241234000080110000') + (
            socket.inet_aton(vip) + socket.inet_aton(gateway)
        )

    def open_socket(self):
        local, remote = self.endpoint
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            try:
                # Leave room for bursts while the forwarding loop is busy.
                if sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) < MIN_RECEIVE_BUFFER:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, MIN_RECEIVE_BUFFER)
            except OSError:
                pass
            sock.bind((local, 0))
            sock.connect(remote)
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise

    def close(self):
        if self.native is not None:
            self.native.release()
            self.native = None

    def _crypt(self, data, iv, decrypt=False):
        if not data:
            return b''
        if self.native is not None:
            try:
                return self.native.transform(data, iv, decrypt)
            except OSError:
                self.close()
        cipher = Cipher(self.algorithm, modes.CBC(iv))
        context = cipher.decryptor() if decrypt else cipher.encryptor()
        return context.update(data) + context.finalize()

    def _encode(self, header, payload):
        iv = self.user_id + os.urandom(12)
        padded = payload + bytes(-len(payload) % 16)
        return PREFIX + iv + header + self._crypt(padded, iv)

    def encode(self, packet):
        packet = validate_ipv4(packet)
        return self._encode(packet[:20], packet[20:])

    def probe(self):
        return self._encode(self.probe_header, PROBE)

    def sized_probe(self, mtu, probe_id):
        header = bytearray(self.probe_header)
        struct.pack_into('!HH', header, 2, mtu, probe_id)
        return self._encode(bytes(header), PROBE.ljust(mtu - 20, b'\0'))

    def _check_probe_size(self, sock, mtu, probe_id):
        packet = self.sized_probe(mtu, probe_id)
        try:
            sock.send(packet)
        except BlockingIOError:
            return False
        except OSError as exc:
            if exc.errno == errno.EMSGSIZE or getattr(exc, 'winerror', None) == 10040:
                return False
            raise
        deadline = time.monotonic() + .35
        while True:
            try:
                wait_ready(sock, False, deadline)
            except TimeoutError:
                return False
            try:
                reply = sock.recv(65535)
                if (reply[PROBE_ID_OFFSET:PROBE_ID_OFFSET + 2] == struct.pack('!H', probe_id)
                        and self.decode(reply) is None):
                    return True
            except (BlockingIOError, ValueError):
                continue

    def discover_path_mtu(self, sock, ceiling):
        """Probe the outbound path before setting the virtual adapter MTU."""
        # CPython does not expose these socket option names on every version.
        option = {'win32': 14, 'darwin': 28}.get(sys.platform)
        if option is None:
            return None
        try:
            previous = sock.getsockopt(socket.IPPROTO_IP, option)
            sock.setsockopt(socket.IPPROTO_IP, option, 1)
        except OSError:
            return None
        try:
            # A legacy acknowledgement is useful only if it echoes this
            # request's IPv4 ID. Older peers may acknowledge only fixed probes.
            seed = int.from_bytes(os.urandom(2), 'big')
            candidates = [ceiling, *(size for size in PATH_MTU_STEPS if size < ceiling)]
            for index, size in enumerate(candidates):
                check_cancelled()
                probe_id = 0x1235 + (seed + index) % (65536 - 0x1235)
                if self._check_probe_size(sock, size, probe_id):
                    if size < ceiling:
                        # Recheck the next larger size once to avoid treating a
                        # single lost datagram as evidence of a path limit.
                        larger_id = 0x1235 + (seed + len(candidates)) % (65536 - 0x1235)
                        larger = candidates[index - 1]
                        if self._check_probe_size(sock, larger, larger_id):
                            return larger
                    return size
        except OSError:
            return None
        finally:
            sock.setsockopt(socket.IPPROTO_IP, option, previous)
        return None

    def decode(self, datagram):
        if len(datagram) < 48 or not datagram.startswith(GATEWAY_PREFIX) or datagram[11] != 16:
            raise ValueError('invalid legacy UDP header')
        header = datagram[28:48]
        length = struct.unpack_from('!H', header, 2)[0] - 20
        encrypted = datagram[48:]
        if length < 0 or len(encrypted) != length + (-length % 16):
            raise ValueError('invalid legacy UDP length')
        payload = self._crypt(encrypted, datagram[12:28], decrypt=True)[:length]
        # The peer can put its own user identifier in the inner header.
        if len(payload) >= 16 and payload.startswith(PROBE[:8]) and payload[12:14] == b'\0\x0f':
            return None
        return validate_ipv4(header + payload)

    def wait_for_probe(self, sock):
        for _ in range(3):
            check_cancelled()
            sock.send(self.probe())
            deadline = time.monotonic() + 2
            while True:
                try:
                    wait_ready(sock, False, deadline)
                except TimeoutError:
                    break
                try:
                    if self.decode(sock.recv(65535)) is None:
                        return
                except (BlockingIOError, ValueError):
                    continue
        raise TimeoutError('网关未回应 UDP 探测。可关闭此配置的 UDP 选项后重新连接')
