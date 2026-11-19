from io import BytesIO
from types import SimpleNamespace
import socket
import struct

import pytest

from multi_vpn import protocol, session
from multi_vpn.model import Profile, RouteRegistry
from multi_vpn.wire import encode_frame, encode_tlv


def auth_reply(*, sms=False, status=0, session_id=37):
    body = bytearray(148)
    struct.pack_into('!iii', body, 0, status, 5, session_id)
    struct.pack_into('!I', body, 40, 99)
    struct.pack_into('!H', body, 0x32, sms)
    body[84:90] = b'cookie'
    return b'\xf0' * 4 + body


class Channel(BytesIO):
    family = socket.AF_INET

    def __init__(self, reply):
        super().__init__(reply)
        self.sent = []

    def recv(self, size):
        return self.read(size)

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        pass


@pytest.mark.parametrize('session_id', [0, 37])
def test_legacy_sms_request_uses_gateway_challenge(session_id):
    with pytest.raises(protocol.LegacySmsRequired) as challenge:
        protocol.legacy_auth_response(Channel(auth_reply(sms=True, session_id=session_id)))
    request = protocol.legacy_sms_request('vpn.example.test', '123456', challenge.value.challenge)
    path = b'GET /checkrdsverificationcode.html?VTID=5'
    if session_id:
        path += b'&UserID=99&SessionID=37'
        assert request.endswith(b'Cookie: SVN_SessionID=cookie\r\n\r\n')
    else:
        assert request.endswith(b'Cookie: UserID=99&SVN_SessionID=cookie;\r\n\r\n')
    assert request.startswith(path + b'&SMSCode=123456&SelectLanguage=2& HTTP/1.1\r\n')


@pytest.mark.parametrize('kind', ['ordinary', 'verified', 'rejected', 'still_pending', 'cancelled'])
def test_legacy_session_waits_for_verified_sms_before_requesting_routes(monkeypatch, kind):
    monkeypatch.setattr(protocol, 'negotiate', lambda *args: 'legacy')
    monkeypatch.setattr(protocol, 'legacy_logout', lambda *args: None)
    monkeypatch.setattr(session, 'routes_for', lambda *args: ['192.0.2.0/24'])
    monkeypatch.setattr(session, 'create_adapter', lambda *args: SimpleNamespace(name='test', index=0, close=lambda: None))
    # Some gateways return a positive status alongside the SMS flag.
    password_tls = Channel(auth_reply(sms=kind != 'ordinary', status=0x12345678))
    sms_tls = Channel(auth_reply(sms=kind == 'still_pending', status=-1 if kind == 'rejected' else 0))
    vip = protocol.legacy_frame(3, socket.inet_aton('192.0.2.10') + bytes(184), 99)
    control_tls = Channel(vip)
    channels = iter([password_tls, control_tls] if kind == 'ordinary' else [password_tls, sms_tls, control_tls])
    opened = []
    events = []

    def emit(_, event, fields):
        events.append(event)
        if event == 'sms':
            assert opened == [password_tls]
            assert password_tls.closed
            if kind == 'cancelled':
                vpn.stop()
            else:
                vpn.answer('sms', '123456')

    vpn = session.Session(Profile(host='vpn.example.test', pin='synthetic', legacy_udp=False),
                          'synthetic', RouteRegistry(), emit)

    def connect():
        tls = next(channels)
        opened.append(tls)
        vpn.sockets.append(tls)
        return tls

    monkeypatch.setattr(vpn, 'connect_tls', connect)
    monkeypatch.setattr(vpn, 'forward', lambda *args: None)
    vpn.run()

    assert ('sms' in events) == (kind != 'ordinary')
    if kind in {'ordinary', 'verified'}:
        assert 'connected' in events and 'error' not in events
        assert control_tls.sent[:-1] == [protocol.legacy_frame(3, user_id=99)]
    else:
        assert 'connected' not in events and not control_tls.sent
        assert ('error' in events) == (kind != 'cancelled')
    assert bool(sms_tls.sent) == (kind not in {'ordinary', 'cancelled'})


def test_v1_sms_still_uses_original_tls_connection(monkeypatch):
    monkeypatch.setattr(protocol, 'negotiate', lambda *args: 'v1')
    monkeypatch.setattr(session, 'routes_for', lambda *args: ['192.0.2.0/24'])
    monkeypatch.setattr(session, 'create_adapter', lambda *args: SimpleNamespace(name='test', index=0, close=lambda: None))
    token = bytes(range(32))
    pending = struct.pack('!I', 1) + bytes(4) + encode_tlv(2, b'\x01')
    approved = bytes(8) + encode_tlv(3, token)
    auth = Channel(encode_frame(1, pending) + encode_frame(1, approved))
    control = Channel(encode_frame(3, b'\0\x08\0\0' + encode_tlv(1, socket.inet_aton('192.0.2.10') + b'\x18')))
    data = Channel(encode_frame(100, b'\0'))
    channels = iter((auth, control, data))
    monkeypatch.setattr(protocol, 'tls_connect', lambda *args, **kwargs: next(channels))
    events = []

    def emit(_, event, fields):
        events.append(event)
        if event == 'sms':
            assert not auth.closed and not control.sent
            vpn.answer('sms', '123456')

    vpn = session.Session(Profile(host='vpn.example.test', pin='synthetic'),
                          'synthetic', RouteRegistry(), emit)
    monkeypatch.setattr(vpn, 'forward', lambda *args: None)
    vpn.run()
    assert 'connected' in events and 'error' not in events
    assert auth.sent[1:] == [protocol.sms_packet('123456')]
    assert control.sent[0] == encode_frame(3, token)
    assert data.sent == [encode_frame(100, token)]
