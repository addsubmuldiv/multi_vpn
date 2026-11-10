import ssl,pytest
from multi_vpn.transport import TLSWriter

class Socket:
    def __init__(self):self.sent=bytearray();self.actions=[2,ssl.SSLWantWriteError(),1,ssl.SSLWantReadError(),99]
    def send(self,data):
        action=self.actions.pop(0) if self.actions else 99
        if isinstance(action,Exception):raise action
        n=min(action,len(data));self.sent.extend(data[:n]);return n

def test_partial_tls_writes_and_temporary_backpressure_do_not_duplicate_frames():
    sock=Socket();writer=TLSWriter(sock);writer.enqueue(b'first');writer.enqueue(b'second')
    for _ in range(4):writer.flush()
    assert sock.sent==b'firstsecond';assert writer.size==0
    assert writer.sent_bytes==len(b'firstsecond')
    assert writer.sent_frames==2

def test_short_stall_survives_but_persistent_stall_fails():
    now=[0.];sock=Socket();writer=TLSWriter(sock,clock=lambda:now[0]);writer.enqueue(b'packet')
    sock.actions=[ssl.SSLWantWriteError()];now[0]=.1;writer.flush()
    now[0]=31
    with pytest.raises(TimeoutError):writer.flush()

def test_output_memory_is_bounded():
    writer=TLSWriter(Socket())
    with pytest.raises(RuntimeError):writer.enqueue(bytes(4*1024*1024+1))
