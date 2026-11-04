import ssl
import pytest
from multi_vpn.transport import ReceiveQueue,TLSWriter,TunnelReader
from multi_vpn.protocol import legacy_frame
from multi_vpn.wire import encode_frame


class Clock:
    now=0.0
    def __call__(self):return self.now


def test_receive_stall_expires_instead_of_buffering_forever():
    clock=Clock();pending=ReceiveQueue(timeout=60,clock=clock)
    class Adapter:
        def write(self,packet):return False
    pending.enqueue(b'packet');clock.now=59
    assert pending.flush(Adapter())==0
    clock.now=61
    with pytest.raises(TimeoutError):pending.flush(Adapter())


def test_receive_queue_keeps_age_of_oldest_packet_after_partial_progress():
    clock=Clock();pending=ReceiveQueue(timeout=60,clock=clock)
    pending.enqueue(b'old');clock.now=40;pending.enqueue(b'new')
    class Adapter:
        count=0
        def write(self,packet):self.count+=1;return self.count==1
    clock.now=59
    assert pending.flush(Adapter())==3
    clock.now=101
    with pytest.raises(TimeoutError):pending.flush(Adapter())


def test_tls_writer_reports_required_readiness_and_preserves_retry_bytes():
    clock=Clock()
    class Socket:
        actions=[ssl.SSLWantReadError(),ssl.SSLWantWriteError(),2,99]
        attempts=[]
        accepted=bytearray()
        def send(self,payload):
            self.attempts.append(bytes(payload));action=self.actions.pop(0)
            if isinstance(action,Exception):raise action
            count=min(action,len(payload));self.accepted.extend(payload[:count]);return count
    socket=Socket();writer=TLSWriter(socket,clock=clock)
    writer.enqueue(b'first')
    writer.flush();assert writer.want=='read'
    writer.enqueue(b'second')
    writer.flush();assert writer.want=='write'
    socket.actions=[2,3,6]
    writer.flush()
    assert socket.attempts[:3]==[b'first']*3
    assert socket.accepted==b'firstsecond' and writer.size==0 and writer.want is None


def test_trickling_tls_cannot_keep_stale_packet_alive_forever():
    clock=Clock()
    class Socket:
        def send(self,payload):return 1
    writer=TLSWriter(Socket(),timeout=30,max_age=120,clock=clock)
    writer.enqueue(bytes(10000))
    for elapsed in (20,40,60,80,100):
        clock.now=elapsed;writer.flush()
    clock.now=121
    with pytest.raises(TimeoutError):writer.flush()


@pytest.mark.parametrize('protocol',['legacy','v1'])
def test_frame_reader_handles_fragmentation_and_does_not_retain_history(protocol):
    clock=Clock();reader=TunnelReader(protocol,clock=clock)
    frame=legacy_frame(7) if protocol=='legacy' else encode_frame(6,b'reply')
    expected=7 if protocol=='legacy' else 6
    for elapsed in range(0,72*3600,8):
        clock.now=elapsed
        assert reader.feed(frame[:3])==[]
        decoded=reader.feed(frame[3:])
        assert decoded[0][0]==expected and reader.size==0


def test_partial_frame_timeout_is_not_reset_by_trickle_or_idle():
    clock=Clock();reader=TunnelReader('v1',timeout=60,clock=clock)
    reader.feed(encode_frame(6,b'abc')[:8])
    clock.now=40;reader.feed(b'a')
    clock.now=61
    with pytest.raises(TimeoutError):reader.check_timeout()
    reader=TunnelReader('legacy',clock=clock)
    clock.now=10000;reader.check_timeout()


def test_frame_reader_rejects_wrong_protocol_and_short_v1_data():
    reader=TunnelReader('v1')
    with pytest.raises(ValueError):reader.feed(legacy_frame(7))
    with pytest.raises(ValueError):TunnelReader('v1').feed(encode_frame(0x66,b'short'))


def test_diagnostics_cannot_block_forwarding_when_disk_is_slow(tmp_path,monkeypatch):
    import threading
    from multi_vpn.diagnostics import EventLog
    log=EventLog(tmp_path)
    entered=threading.Event();release=threading.Event()
    def slow_disk(record):
        assert threading.current_thread() is not threading.main_thread()
        entered.set();release.wait(5)
    monkeypatch.setattr(log.handler,'handle',slow_disk)
    try:
        assert log.write('profile','traffic',{'tx':1})
        assert entered.wait(2)
        results=[log.write('profile','traffic',{'tx':sequence}) for sequence in range(300)]
        assert not all(results) and log.dropped>0
    finally:release.set();log.close()


def test_transport_enables_keepalive_without_requiring_optional_platform_options():
    import socket
    from multi_vpn.protocol import configure_transport
    class Socket:
        options=[]
        def setsockopt(self,level,option,value):self.options.append((level,option,value))
        def ioctl(self,*args):raise OSError('unsupported')
    transport=Socket();configure_transport(transport)
    assert (socket.IPPROTO_TCP,socket.TCP_NODELAY,1) in transport.options
    assert (socket.SOL_SOCKET,socket.SO_KEEPALIVE,1) in transport.options


def test_control_heartbeats_do_not_hide_stalled_data_channel(monkeypatch):
    from multi_vpn.session import Session
    from multi_vpn.model import Profile,RouteRegistry
    from multi_vpn.wire import icmp_echo
    import multi_vpn.session as implementation
    clock=Clock();events=[]
    packet=icmp_echo('192.0.2.1','192.0.2.2')
    session=Session(Profile(),'secret',RouteRegistry(),lambda profile,event,fields:events.append((event,fields)))
    class Socket:
        is_data=False
        def setblocking(self,value):pass
        def send(self,payload):return len(payload)
        def pending(self):return 0
        def recv(self,size):return encode_frame(0x66,bytes(8)+packet) if self.is_data else encode_frame(6,b'heartbeat')
    class Adapter:
        sent=False
        def read(self):
            if self.sent:return None
            self.sent=True;return packet
        def write(self,payload):return True
    control=Socket();data=Socket();data.is_data=True;session.adapter=Adapter()
    def select_ready(*args):
        clock.now+=1
        if clock.now>=75:session.stop()
        return ([data] if clock.now==65 else [control] if clock.now%5==0 else []),[],[]
    monkeypatch.setattr(implementation.time,'monotonic',clock)
    monkeypatch.setattr(implementation.select,'select',select_ready)
    session.forward(control,data,'v1',0,bytes(32))
    states=[fields['state'] for event,fields in events if event=='state']
    assert states==['degraded','connected']
    degraded=[fields for event,fields in events if event=='traffic' and fields['last_receive_age']>=30 and fields['last_receive_age']<60]
    assert degraded and any(fields['last_gateway_age']<5 for fields in degraded)


def test_many_queue_cycles_release_packet_history():
    class Socket:
        def send(self,payload):return len(payload)
    class Adapter:
        def write(self,packet):return True
    writer=TLSWriter(Socket());pending=ReceiveQueue();adapter=Adapter()
    for sequence in range(20000):
        writer.enqueue(b'outbound');writer.flush()
        pending.enqueue(b'inbound');assert pending.flush(adapter)==7
    assert not writer.queue and not writer.timestamps and writer.size==0 and writer.age==0
    assert not pending.queue and not pending.timestamps and pending.size==0 and pending.age==0
