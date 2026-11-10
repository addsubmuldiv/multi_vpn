from collections import deque
from io import BytesIO
import socket
import struct
import sys
import threading
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from multi_vpn.legacy_udp import LegacyUdp, PREFIX
import multi_vpn.legacy_udp as udp_implementation
import multi_vpn.session as implementation
from multi_vpn.model import Profile, RouteRegistry, Store
from multi_vpn.protocol import legacy_frame
from multi_vpn.session import GatewayKickout, Session, legacy_exchange
from multi_vpn.wire import icmp_echo


KEY = bytes(range(16))
UID = 0x12345678
VIP = '192.0.2.10'
GATEWAY = '127.0.0.1'


def from_gateway(header, payload):
    iv = bytes(range(16, 32))
    cipher = Cipher(algorithms.AES128(KEY), modes.CBC(iv)).encryptor()
    ciphertext = cipher.update(payload + bytes(-len(payload) % 16)) + cipher.finalize()
    return bytes.fromhex('fefcefbec192a4d6011c0010') + iv + header + ciphertext


class Control:
    family = socket.AF_INET

    def __init__(self, port):
        self.sent = []
        self.timeout = 15
        self.closed = False
        self.reply = BytesIO(legacy_frame(13, struct.pack('!I', 3) + KEY) +
                             legacy_frame(26, struct.pack('!H', port)))

    def getpeername(self):
        return GATEWAY, 49999

    def getsockname(self):
        return GATEWAY, 55555

    def recv(self, size):
        return self.reply.read(size)

    def sendall(self, data):
        self.sent.append(data)

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


def config_frame():
    payload = socket.inet_aton(VIP) + bytes(184)
    return legacy_frame(3, payload, UID)


def test_existing_profiles_prefer_udp_unless_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv('MULTIVPN_DATA_DIR', str(tmp_path))
    store = Store()
    store.path.write_text('[{"id":"old"},{"id":"tcp","legacy_udp":false}]', encoding='utf-8')
    default, opt_out = store.load()
    assert default.legacy_udp is True
    assert opt_out.legacy_udp is False
    control = Control(443)
    control.reply = BytesIO(config_frame())
    session = Session(opt_out, '', RouteRegistry(), lambda *args: None)
    assert session.open_legacy_tunnel(control, UID)[1:] == (control, control, None)
    assert control.sent == [legacy_frame(3, user_id=UID)]


@pytest.mark.parametrize('payload_size', [12, 1372])
def test_probe_and_packet_through_udp_socket(payload_size):
    session = Session(Profile(), '', RouteRegistry(), lambda *args: None)
    outgoing = icmp_echo(VIP, '192.0.2.22', payload=b'>' * payload_size)
    incoming = icmp_echo('192.0.2.22', VIP, payload=b'<' * payload_size)
    observed = deque()
    received = []
    packets = deque([outgoing])

    class Adapter:
        def read(self):
            return packets.popleft() if packets else None

        def write(self, packet):
            received.append(packet)
            session.stop()
            return True

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as gateway:
        gateway.bind((GATEWAY, 0))
        gateway.settimeout(2)
        control = Control(gateway.getsockname()[1])
        control.reply = BytesIO(config_frame() + control.reply.read())

        def peer():
            probe, address = gateway.recvfrom(2048)
            observed.append(probe)
            gateway.sendto(from_gateway(probe[28:48], legacy_frame(15, user_id=UID)), address)
            packet, address = gateway.recvfrom(2048)
            observed.append(packet)
            gateway.sendto(from_gateway(incoming[:20], incoming[20:]), address)

        worker = threading.Thread(target=peer)
        worker.start()
        deadline = threading.Timer(3, session.stop)
        try:
            cfg, negotiated_control, data, udp = session.open_legacy_tunnel(control, UID)
            assert cfg['vip'] == VIP and negotiated_control is control
            assert control.sent == [legacy_frame(3, user_id=UID),
                                    legacy_frame(13, bytes.fromhex('00000004'), UID),
                                    legacy_frame(26, bytes.fromhex('00000004'), UID)]
            # A socket pair supplies an idle, selectable TLS-control stand-in.
            local, remote = socket.socketpair()
            with local, remote:
                class IdleControl:
                    fileno = staticmethod(local.fileno)
                    setblocking = staticmethod(local.setblocking)

                    def pending(self):
                        return 0

                session.adapter = Adapter()
                deadline.start()
                session.forward(IdleControl(), data, 'legacy', UID, None, udp)
            assert received == [incoming]
            probe, packet = observed
            assert len(probe) == 64 and probe[:16] == PREFIX + struct.pack('!I', UID)
            assert probe[28:48] == bytes.fromhex('458000241234000080110000c000020a7f000001')
            assert packet[28:48] == outgoing[:20]
            assert len(packet) + 28 <= 1500
            for wire, payload in [(probe, legacy_frame(14)), (packet, outgoing[20:])]:
                decoder = Cipher(algorithms.AES128(KEY), modes.CBC(wire[12:28])).decryptor()
                assert (decoder.update(wire[48:]) + decoder.finalize())[:len(payload)] == payload
            with pytest.raises(ValueError, match='length'):
                udp.decode(from_gateway(incoming[:20], incoming[20:])[:-1])
        finally:
            deadline.cancel()
            for sock in session.sockets:
                sock.close()
            worker.join(timeout=3)


def test_failed_probe_switches_transport_on_existing_control(monkeypatch):
    session = Session(Profile(), '', RouteRegistry(), lambda *args: None)
    control = Control(443)

    def no_reply(self, sock):
        raise TimeoutError

    monkeypatch.setattr(LegacyUdp, 'wait_for_probe', no_reply)
    assert session.open_legacy_udp(control, UID, VIP) == (None, control)
    assert control.sent[-1] == legacy_frame(16, user_id=UID)
    assert not session.sockets


@pytest.mark.parametrize('failure', ['timeout', 'unsupported'])
def test_udp_negotiation_falls_back_to_fresh_tls_without_reauthentication(monkeypatch, failure):
    session = Session(Profile(), '', RouteRegistry(), lambda *args: None)
    first, fallback = Control(443), Control(443)
    first.reply = BytesIO(config_frame() + (legacy_frame(13, bytes(4)) if failure == 'unsupported' else b''))
    if failure == 'timeout':
        def timeout_after_config(size):
            chunk = first.reply.read(size)
            if not chunk:
                assert first.gettimeout() == 5
                raise TimeoutError
            return chunk
        monkeypatch.setattr(first, 'recv', timeout_after_config)
    fallback.reply = BytesIO(config_frame())
    monkeypatch.setattr(session, 'connect_tls', lambda: fallback)
    cfg, control, data, udp = session.open_legacy_tunnel(first, UID)
    assert cfg['vip'] == VIP
    assert first.closed and first.gettimeout() == 15
    assert (control, data, udp) == (fallback, fallback, None)
    assert first.sent == [legacy_frame(3, user_id=UID), legacy_frame(13, bytes.fromhex('00000004'), UID)]
    assert fallback.sent == [legacy_frame(3, user_id=UID)]


def test_legacy_kickout_during_setup():
    control = Control(443)
    control.reply = BytesIO(legacy_frame(7) + legacy_frame(8))
    with pytest.raises(GatewayKickout):
        legacy_exchange(control, UID, 3)


def test_udp_negotiation_does_not_retry_on_kickout(monkeypatch):
    session = Session(Profile(), '', RouteRegistry(), lambda *args: None)
    control = Control(443)
    control.reply = BytesIO(config_frame() + legacy_frame(8))
    monkeypatch.setattr(session, 'connect_tls', lambda: pytest.fail('unexpected retry after kickout'))
    with pytest.raises(GatewayKickout):
        session.open_legacy_tunnel(control, UID)


def test_udp_timeout_switches_before_sending_tcp_data(monkeypatch):
    events = []
    now = 0
    session = Session(Profile(), '', RouteRegistry(), lambda _, name, fields: events.append(name))
    outgoing = icmp_echo(VIP, '192.0.2.22', payload=b'after switch')
    incoming = icmp_echo('192.0.2.22', VIP, payload=b'from TLS')
    queued = deque([outgoing])

    class Socket:
        def __init__(self):
            self.sent = []
            self.closed = False

        def setblocking(self, enabled):
            pass

        def pending(self):
            return 0

        def close(self):
            self.closed = True

        def send(self, payload):
            self.sent.append(bytes(payload))
            return len(payload)

        def recv(self, size):
            return legacy_frame(2, incoming, UID)

    class Adapter:
        def read(self):
            return queued.popleft() if 'transport_changed' in events and queued else None

        def write(self, packet):
            assert packet == incoming
            session.stop()
            return True

    control, data = Socket(), Socket()

    def poll(read, write, exceptional, timeout):
        nonlocal now
        now += 8
        assert now <= 72, 'UDP fallback did not resume TLS forwarding'
        if control.sent and control.sent[-1] == legacy_frame(2, outgoing, UID):
            return [control], [], []
        return [], [], []

    monkeypatch.setattr(implementation, 'time', SimpleNamespace(monotonic=lambda: now))
    monkeypatch.setattr(implementation.select, 'select', poll)
    session.adapter = Adapter()
    session.sockets.append(data)
    session.forward(control, data, 'legacy', UID, None, LegacyUdp(KEY, UID, VIP, GATEWAY))
    assert data.sent and data.closed
    assert control.sent.index(legacy_frame(16, user_id=UID)) < control.sent.index(legacy_frame(2, outgoing, UID))
    assert session.rx == len(incoming)


@pytest.mark.parametrize('probe_succeeds', [True, False])
def test_udp_socket_error_rebuilds_once_with_live_control(monkeypatch, probe_succeeds):
    events = []
    now = 0
    session = Session(Profile(), '', RouteRegistry(), lambda _, event, fields: events.append(event))
    udp = LegacyUdp(KEY, UID, VIP, GATEWAY)
    udp.endpoint = (GATEWAY, (GATEWAY, 443))
    incoming = icmp_echo('192.0.2.22', VIP)

    class Socket:
        def __init__(self, *replies):
            self.sent = []
            self.replies = deque(replies)
            self.closed = False

        def setblocking(self, enabled):pass
        def pending(self):return 0
        def close(self):self.closed = True
        def send(self, payload):
            self.sent.append(bytes(payload))
            return len(payload)
        def recv(self, size):
            if not self.replies:raise BlockingIOError
            reply = self.replies.popleft()
            if isinstance(reply, Exception):raise reply
            return reply

    control = Socket()
    failed = Socket(ConnectionResetError())
    header = udp.probe_header
    recovered = Socket(
        from_gateway(header, legacy_frame(15, user_id=UID)),
        from_gateway(incoming[:20], incoming[20:]),
    ) if probe_succeeds else Socket()
    replacement_attempts = []

    def open_socket():
        replacement_attempts.append(True)
        return recovered

    def poll(read, write, exceptional, timeout):
        nonlocal now
        now += 1
        assert now < 20, 'repair never completed'
        if control.sent and legacy_frame(16, user_id=UID) in control.sent and not probe_succeeds:
            control.replies.append(legacy_frame(2, incoming, UID))
        ready = [sock for sock in read if sock.replies and (sock is not recovered or recovered.sent)]
        return ready, [], []

    class Adapter:
        def read(self):return None
        def write(self, packet):
            assert packet == incoming
            session.stop()
            return True

    session.adapter = Adapter()
    session.sockets = [control, failed]
    monkeypatch.setattr(udp, 'open_socket', open_socket)
    monkeypatch.setattr(implementation, 'time', SimpleNamespace(monotonic=lambda: now))
    monkeypatch.setattr(implementation.select, 'select', poll)
    session.forward(control, failed, 'legacy', UID, None, udp)
    assert replacement_attempts == [True]
    assert failed.closed and not control.closed
    assert recovered.sent and session.rx == len(incoming)
    assert recovered.closed is not probe_succeeds
    assert ('transport_changed' in events) is not probe_succeeds
    assert session.metrics['udp_repairs'] == 1


@pytest.mark.skipif(sys.platform not in ('win32', 'darwin'), reason='uses a native IPv4 DF option')
@pytest.mark.parametrize('echo_id,larger_recovers,expected', [
    (True, False, 1320),
    (True, True, 1360),
    (False, False, None),
])
def test_path_mtu_requires_matching_probe_and_restores_socket(monkeypatch, echo_id, larger_recovers, expected):
    udp = LegacyUdp(KEY, UID, VIP, GATEWAY)
    sent = []

    class Path:
        df = 0
        reply = None

        def getsockopt(self, level, option):
            assert level == socket.IPPROTO_IP
            return self.df

        def setsockopt(self, level, option, value):
            self.df = value

        def send(self, request):
            assert self.df == 1
            size, probe_id = struct.unpack_from('!HH', request, 30)
            sent.append((size, probe_id))
            assert len(request) == 48 + (size - 20 + 15) // 16 * 16
            if size <= 1320 or (larger_recovers and size == 1360 and len(sent) == 4):
                ack = bytearray(request[28:48])
                struct.pack_into('!HH', ack, 2, 36, probe_id if echo_id else 0x1234)
                self.reply = from_gateway(ack, legacy_frame(15, user_id=UID))
            return len(request)

        def recv(self, size):
            result, self.reply = self.reply, None
            return result

    def ready(path, writing, deadline):
        if path.reply is None:
            raise TimeoutError

    path = Path()
    monkeypatch.setattr(udp_implementation, 'wait_ready', ready)
    assert udp.discover_path_mtu(path, 1400) == expected
    assert path.df == 0
    assert len({probe_id for _, probe_id in sent}) == len(sent)
    assert all(probe_id != 0x1234 for _, probe_id in sent)
