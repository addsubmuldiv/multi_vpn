"""Bounded nonblocking TLS output; retry only bytes not yet accepted."""
from collections import deque
import ssl,time

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
