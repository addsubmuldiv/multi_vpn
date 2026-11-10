import time
from multi_vpn.session import Session
from multi_vpn.model import Profile,RouteRegistry

def test_cancel_while_waiting_for_sms():
    from multi_vpn.session import Cancelled
    session=Session(Profile(),'secret',RouteRegistry(),lambda *a:None)
    session.stop()
    try:session.wait('sms')
    except Cancelled:pass
    else:assert False,'Cancellation must abort authentication wait'

def test_independent_credentials_and_event_queues():
    registry=RouteRegistry()
    a=Session(Profile(),'one',registry,lambda *a:None);b=Session(Profile(),'two',registry,lambda *a:None)
    a.answer('sms','synthetic')
    assert b.answers.empty()
    assert a.wait('sms')=='synthetic'


def test_legacy_burst_preserves_frame_writes_during_socket_backpressure(monkeypatch):
    from collections import deque
    import ssl
    import multi_vpn.session as implementation
    from multi_vpn.protocol import legacy_frame
    from multi_vpn.wire import icmp_echo

    packets = [icmp_echo('192.0.2.1', '192.0.2.2', sequence=i, payload=bytes(1200))
               for i in range(32)]
    expected = b''.join(legacy_frame(2, packet, 123) for packet in packets)
    outgoing = deque(packets)
    session = Session(Profile(), '', RouteRegistry(), lambda *args: None)

    class Adapter:
        def read(self):
            return outgoing.popleft() if outgoing else None

    class Socket:
        def __init__(self):
            self.attempts = []
            self.accepted = bytearray()

        def setblocking(self, enabled):
            pass

        def pending(self):
            return 0

        def send(self, payload):
            self.attempts.append(bytes(payload))
            if len(self.attempts) == 1:
                raise ssl.SSLWantWriteError()
            count = 17 if len(self.attempts) == 2 else len(payload)
            self.accepted.extend(payload[:count])
            if len(self.accepted) == len(expected):
                session.stop()
            return count

    channel = Socket()
    polls = 0

    def ready(read, write, exceptional, timeout):
        nonlocal polls
        polls += 1
        assert polls <= 5, 'Legacy writer did not drain the burst'
        return [], write, []

    monkeypatch.setattr(implementation.select, 'select', ready)
    session.adapter = Adapter()
    session.forward(channel, channel, 'legacy', 123, None)
    assert channel.accepted == expected
    assert channel.attempts[0] == channel.attempts[1]
    assert max(map(len, channel.attempts)) == len(legacy_frame(2, packets[0], 123))
    assert len(channel.attempts) == len(packets) + 2
