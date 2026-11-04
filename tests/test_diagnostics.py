import json
from multi_vpn.diagnostics import EventLog
from multi_vpn.transport import ReceiveQueue,ReceiveHealth


def test_log_persists_only_safe_fields_and_rotates(tmp_path):
    log=EventLog(tmp_path,max_bytes=200,backups=2)
    for sequence in range(20):
        assert log.write('profile','traffic',{'tx':sequence,'password':'SECRET','token':'SECRET','message':'SECRET'})
    files=list(tmp_path.glob('multi-vpn.log*'))
    assert 1<=len(files)<=3
    rows=[json.loads(line) for path in files for line in path.read_text(encoding='utf-8').splitlines()]
    assert rows and all(row['event']=='traffic' for row in rows)
    assert all('SECRET' not in path.read_text(encoding='utf-8') for path in files)
    log.close()


def test_logging_failure_does_not_break_session(tmp_path):
    blocked=tmp_path/'file'
    blocked.write_text('not a directory')
    log=EventLog(blocked)
    assert not log.write('profile','state',{'state':'connected'})


def test_receive_queue_retries_without_loss_or_double_delivery():
    delivered=[]
    class Adapter:
        blocked=True
        def write(self,packet):
            if self.blocked:return False
            delivered.append(packet)
    adapter=Adapter();pending=ReceiveQueue()
    pending.enqueue(b'one');pending.enqueue(b'two')
    assert pending.flush(adapter)==0
    assert pending.size==6 and pending.blocked==1
    adapter.blocked=False
    assert pending.flush(adapter)==6
    assert pending.size==0 and delivered==[b'one',b'two']
    assert pending.flush(adapter)==0


def test_receive_queue_handles_nonblocking_adapter_and_is_bounded():
    import pytest
    class Adapter:
        def write(self,packet):raise BlockingIOError()
    pending=ReceiveQueue(limit=4);pending.enqueue(b'abcd')
    assert pending.flush(Adapter())==0 and pending.size==4
    with pytest.raises(BufferError):pending.enqueue(b'e')


def test_no_response_warning_is_not_an_idle_disconnect():
    health=ReceiveHealth(now=0,timeout=30)
    assert health.check(100) is None
    health.sent(100)
    assert health.check(129) is None
    assert health.check(131)=='degraded'
    assert health.check(200) is None
    health.received(201)
    assert health.check(201)=='connected'
    assert health.check(400) is None


def test_forward_retries_adapter_and_counts_only_delivered_packets(monkeypatch):
    from multi_vpn.session import Session
    from multi_vpn.model import Profile,RouteRegistry
    from multi_vpn.protocol import legacy_frame
    from multi_vpn.wire import icmp_echo
    import multi_vpn.session as implementation
    packets=[icmp_echo('192.0.2.1','192.0.2.2',sequence=sequence) for sequence in (1,2)]
    session=Session(Profile(),'secret',RouteRegistry(),lambda *args:None)
    class Socket:
        payload=b''.join(legacy_frame(2,packet,1) for packet in packets)
        def setblocking(self,value):pass
        def pending(self):return len(self.payload)
        def recv(self,size):
            payload=self.payload;self.payload=b'';return payload
        def send(self,payload):return len(payload)
    class Adapter:
        delivered=[]
        attempts=0
        def read(self):return None
        def write(self,packet):
            self.attempts+=1
            if self.attempts==1:return False
            self.delivered.append(packet)
            if len(self.delivered)==2:session.stop()
            return True
    adapter=Adapter();session.adapter=adapter;socket=Socket()
    monkeypatch.setattr(implementation.select,'select',lambda *args:([],[],[]))
    session.forward(socket,socket,'legacy',1,None)
    assert adapter.delivered==packets and adapter.attempts==3
    assert session.rx==sum(map(len,packets))


def test_full_legacy_receive_queue_does_not_select_empty_windows_sockets(monkeypatch):
    from multi_vpn.session import Session
    from multi_vpn.model import Profile,RouteRegistry
    import multi_vpn.session as implementation
    session=Session(Profile(),'secret',RouteRegistry(),lambda *args:None)
    class Pending:
        size=1024*1024
        blocked=1
        def flush(self,adapter):return 0
    class Adapter:
        def read(self):return None
    class Socket:
        def setblocking(self,value):pass
    def forbidden_select(*args):raise AssertionError('unexpected select during receive backpressure')
    waits=[]
    def wait(timeout):waits.append(timeout);session.stop()
    session.adapter=Adapter();socket=Socket()
    monkeypatch.setattr(implementation,'ReceiveQueue',Pending)
    monkeypatch.setattr(implementation.select,'select',forbidden_select)
    monkeypatch.setattr(session.cancel,'wait',wait)
    session.forward(socket,socket,'legacy',1,None)
    assert waits==[.005]
