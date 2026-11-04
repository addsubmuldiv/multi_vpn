"""Bounded nonblocking TLS output; retry only bytes not yet accepted."""
from collections import deque
import ssl,struct,time

class SendStallError(TimeoutError):pass
class SendQueueAgeError(TimeoutError):pass
class AdapterStallError(TimeoutError):pass
class FrameStallError(TimeoutError):pass

class TunnelReader:
    def __init__(self,protocol,timeout=120,clock=time.monotonic):
        if protocol not in ('legacy','v1'):raise ValueError('unknown tunnel protocol')
        self.protocol=protocol;self.timeout=timeout;self.clock=clock
        self.buffer=bytearray();self.started=None
    @property
    def size(self):return len(self.buffer)
    @property
    def age(self):return 0 if self.started is None else self.clock()-self.started
    def check_timeout(self):
        if self.started is not None and self.age>=self.timeout:raise FrameStallError('隧道报文长期不完整，请检查链路')
    def feed(self,chunk):
        self.check_timeout()
        if chunk and not self.buffer:self.started=self.clock()
        self.buffer.extend(chunk)
        if len(self.buffer)>2*(65535+16):raise BufferError('隧道报文接收缓冲区超限')
        frames=[];header=16 if self.protocol=='legacy' else 8
        while len(self.buffer)>=header:
            if self.protocol=='legacy':
                first,second,user,command,size=struct.unpack_from('!IIIHH',self.buffer)
                if (first,second)!=(0xfefcefbe,0xc192a4d6):raise ValueError('无效的数据报头')
            else:
                magic,version,command,size=struct.unpack_from('!4sBBH',self.buffer)
                if magic!=b'\xc1\x92\xa4\xd6' or version!=1:raise ValueError('无效的新版数据报头')
            if len(self.buffer)<header+size:break
            payload=bytes(self.buffer[header:header+size]);del self.buffer[:header+size]
            if self.protocol=='v1' and command==0x66 and len(payload)<8:raise ValueError('新版数据报缺少保留字段')
            frames.append((command,payload));self.started=self.clock() if self.buffer else None
        return frames

class ReceiveQueue:
    def __init__(self,limit=4*1024*1024,timeout=60,clock=time.monotonic):
        self.queue=deque();self.size=0;self.limit=limit;self.blocked=0
        self.timestamps=deque();self.timeout=timeout;self.clock=clock
    @property
    def age(self):return self.clock()-self.timestamps[0] if self.timestamps else 0
    def enqueue(self,packet):
        if self.size+len(packet)>self.limit:raise BufferError('系统网卡接收队列已满，请检查本机负载')
        self.queue.append(packet);self.timestamps.append(self.clock());self.size+=len(packet)
    def flush(self,adapter):
        delivered=0
        for _ in range(256):
            if not self.queue:break
            if self.age>=self.timeout:raise AdapterStallError('系统网卡连续积压数据超过时限，请检查本机负载')
            packet=self.queue[0]
            try:accepted=adapter.write(packet)
            except BlockingIOError:accepted=False
            if accepted is False:
                self.blocked+=1;break
            self.queue.popleft();self.timestamps.popleft();self.size-=len(packet);delivered+=len(packet)
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
    def __init__(self,sock,timeout=30,clock=time.monotonic,max_age=120):
        self.sock=sock;self.timeout=timeout;self.clock=clock
        self.queue=deque();self.offset=0;self.size=0;self.progress=clock()
        self.timestamps=deque();self.max_age=max_age;self.want=None
    @property
    def age(self):return self.clock()-self.timestamps[0] if self.timestamps else 0
    def check_timeout(self):
        if not self.queue:return
        if self.clock()-self.progress>=self.timeout:raise SendStallError('隧道连续 30 秒无法发送数据，请检查网络或网关连接')
        if self.age>=self.max_age:raise SendQueueAgeError('隧道发送数据积压超过时限，请检查网络或网关负载')
    def enqueue(self,data):
        if self.size+len(data)>4*1024*1024:raise RuntimeError('隧道发送队列已满，网关持续未接收数据')
        if not self.queue:self.progress=self.clock()
        self.queue.append(data);self.timestamps.append(self.clock());self.size+=len(data)
    def flush(self):
        for _ in range(32):
            if not self.queue:self.want=None;return
            self.check_timeout()
            try:n=self.sock.send(memoryview(self.queue[0])[self.offset:])
            except ssl.SSLWantReadError:self.want='read';return
            except (ssl.SSLWantWriteError,BlockingIOError):self.want='write';return
            if n==0:raise ConnectionError('网关已关闭发送连接')
            self.want=None;self.progress=self.clock();self.offset+=n;self.size-=n
            if self.offset==len(self.queue[0]):self.queue.popleft();self.timestamps.popleft();self.offset=0
