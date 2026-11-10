"""Legacy IPv4 UDP data channel with an explicit IV in each datagram."""
import os
import socket
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .operations import check_cancelled, wait_ready
from .protocol import legacy_frame
from .wire import validate_ipv4


PREFIX = bytes.fromhex('fefcefbec192a4d6021c0010')
GATEWAY_PREFIX = bytes.fromhex('fefcefbec192a4d6011c')
PROBE = legacy_frame(14)


class LegacyUdp:
    def __init__(self, key, user_id, vip, gateway):
        self.algorithm = algorithms.AES128(key)
        self.user_id = struct.pack('!I', user_id)
        self.probe_header = bytes.fromhex('458000241234000080110000') + (
            socket.inet_aton(vip) + socket.inet_aton(gateway)
        )

    def _encode(self, header, payload):
        iv = self.user_id + os.urandom(12)
        encryptor = Cipher(self.algorithm, modes.CBC(iv)).encryptor()
        padded = payload + bytes(-len(payload) % 16)
        return PREFIX + iv + header + encryptor.update(padded) + encryptor.finalize()

    def encode(self, packet):
        packet = validate_ipv4(packet)
        return self._encode(packet[:20], packet[20:])

    def probe(self):
        return self._encode(self.probe_header, PROBE)

    def decode(self, datagram):
        if len(datagram) < 48 or not datagram.startswith(GATEWAY_PREFIX) or datagram[11] != 16:
            raise ValueError('invalid legacy UDP header')
        header = datagram[28:48]
        length = struct.unpack_from('!H', header, 2)[0] - 20
        encrypted = datagram[48:]
        if length < 0 or len(encrypted) != length + (-length % 16):
            raise ValueError('invalid legacy UDP length')
        decryptor = Cipher(self.algorithm, modes.CBC(datagram[12:28])).decryptor()
        payload = (decryptor.update(encrypted) + decryptor.finalize())[:length]
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
