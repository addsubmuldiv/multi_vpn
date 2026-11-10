from collections import deque
from io import BytesIO
from types import SimpleNamespace

import pytest

import multi_vpn.session as implementation
from multi_vpn.model import Profile, RouteRegistry
from multi_vpn.protocol import ProtocolError
from multi_vpn.session import DataRebind, Session
from multi_vpn.wire import data_frame, encode_frame, icmp_echo


TOKEN = bytes(range(32))


@pytest.mark.parametrize('result', [0, 1])
def test_v1_data_binding_reuses_session_token(monkeypatch, result):
    class DataSocket:
        closed = False
        sent = None
        recv = BytesIO(encode_frame(0x64, bytes([result]))).read

        def sendall(self, packet):
            self.sent = packet

        def close(self):
            self.closed = True

    data = DataSocket()
    monkeypatch.setattr(implementation.p, 'tls_connect', lambda *args, **kwargs: data)
    session = Session(Profile(), '', RouteRegistry(), lambda *args: None)
    if result:
        with pytest.raises(ProtocolError):
            session.open_v1_data(TOKEN)
        assert data.closed
    else:
        assert session.open_v1_data(TOKEN) is data
        assert not data.closed
    assert data.sent == encode_frame(0x64, TOKEN)


def test_data_rebind_retries_transient_error_and_closes_unclaimed_socket():
    attempts = []
    class Socket:
        closed = False
        def close(self):self.closed = True
    sock = Socket()

    def open_data(token, *, timeout, read_timeout):
        assert token == TOKEN and timeout == read_timeout == 4
        attempts.append(token)
        if len(attempts) == 1:
            raise ConnectionResetError()
        return sock

    with DataRebind(open_data, TOKEN) as rebind:
        rebind.start()
        assert rebind.future.result(timeout=3) is sock
    assert len(attempts) == 2
    assert sock.closed


def test_data_eof_recovers_without_losing_control_channel(monkeypatch):
    now = 0
    events = []
    packet = icmp_echo('192.0.2.2', '192.0.2.1')
    session = Session(Profile(), '', RouteRegistry(), lambda _, event, fields: events.append((event, fields)))

    class Channel:
        def __init__(self, *replies):
            self.replies = deque(replies)
            self.sent = []
            self.closed = False

        def setblocking(self, enabled):pass
        def pending(self):return 0
        def close(self):self.closed = True
        def send(self, data):
            self.sent.append(bytes(data))
            return len(data)
        def recv(self, size):
            if not self.replies:raise BlockingIOError
            return self.replies.popleft()

    control = Channel()
    broken = Channel(data_frame(packet)[:5], b'')
    repaired = Channel(encode_frame(0x65) + data_frame(packet))
    attempts = []

    class Rebind:
        def start(self):
            attempts.append(now)
        def take(self):
            return repaired if now >= 12 else None

    class Adapter:
        def read(self):return None
        def write(self, data):
            assert data == packet
            session.stop()
            return True

    def poll(read, write, exceptional, timeout):
        nonlocal now
        now += 1
        assert now < 20, 'TLS tunnel did not recover'
        if now % 3 == 0:
            control.replies.append(encode_frame(6))
        return [sock for sock in read if sock.replies], [], []

    session.adapter = Adapter()
    session.sockets = [control, broken]
    monkeypatch.setattr(implementation, 'time', SimpleNamespace(monotonic=lambda: now))
    monkeypatch.setattr(implementation.select, 'select', poll)
    session._forward(control, broken, 'v1', 0, TOKEN, None, Rebind())
    assert attempts == [1]
    assert broken.closed and not control.closed and not repaired.closed
    assert session.sockets == [control, repaired]
    assert control.sent == [encode_frame(6, TOKEN + bytes.fromhex('00000001'))]
    assert session.rx == len(packet)
    assert session.metrics['tls_data_repairs'] == 1
    assert session.metrics['tls_control_acks'] >= 3
    assert session.metrics['tls_data_acks'] == 1
