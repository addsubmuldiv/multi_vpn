"""Bounded nonblocking TLS output; retry only bytes not yet accepted."""
from collections import deque
import ssl,time

class ReceiveQueue:
    def __init__(self,limit=4*1024*1024):
        self.queue=deque();self.size=0;self.limit=limit;self.blocked=0
    def enqueue(self,packet):
        if self.size+len(packet)>self.limit:raise BufferError('系统网卡接收队列已满，请检查本机负载')
        self.queue.append(packet);self.size+=len(packet)
    def flush(self,adapter):
        delivered=0
        for _ in range(256):
            if not self.queue:break
            packet=self.queue[0]
            try:accepted=adapter.write(packet)
            except BlockingIOError:accepted=False
            if accepted is False:
                self.blocked+=1;break
            self.queue.popleft();self.size-=len(packet);delivered+=len(packet)
        return delivered

class ReceiveHealth:
    def __init__(self,now,timeout=30):
        self.last_receive=now;self.waiting_since=None;self.timeout=timeout;self.degraded=False
    def sent(self,now):
        if self.waiting_since is None:self.waiting_since=now
    def received(self,now):
        self.last_receive=now;self.waiting_since=None
    def check(self,now):
        if self.waiting_since is not None and now-self.waiting_since>=self.timeout:
            if not self.degraded:self.degraded=True;return 'degraded'
        elif self.degraded:self.degraded=False;return 'connected'
        return None

class TLSWriter:
    def __init__(self,sock,timeout=30,clock=time.monotonic):
        self.sock=sock;self.timeout=timeout;self.clock=clock
        self.queue=deque();self.offset=0;self.size=0;self.progress=clock()
    def enqueue(self,data):
        if self.size+len(data)>4*1024*1024:raise RuntimeError('隧道发送队列已满，网关持续未接收数据')
        if not self.queue:self.progress=self.clock()
        self.queue.append(data);self.size+=len(data)
    def flush(self):
        for _ in range(32):
            if not self.queue:return
            if self.clock()-self.progress>=self.timeout:
                raise TimeoutError('隧道连续 30 秒无法发送数据，请检查网络或网关连接')
            try:n=self.sock.send(memoryview(self.queue[0])[self.offset:])
            except (ssl.SSLWantReadError,ssl.SSLWantWriteError,BlockingIOError):return
            if n==0:raise ConnectionError('网关已关闭发送连接')
            self.progress=self.clock();self.offset+=n;self.size-=n
            if self.offset==len(self.queue[0]):self.queue.popleft();self.offset=0
