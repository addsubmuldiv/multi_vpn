"""Per-session protocol and real OS packet forwarding; no shared tunnel state."""
import hashlib,ipaddress,queue,select,socket,ssl,struct,threading,time,uuid
from . import protocol as p
from .wire import encode_frame,read_frame,FrameReader,parse_vip,auth_v1,validate_ipv4
from .platforms import create_adapter
from .transport import TLSWriter

class Cancelled(Exception):pass

def routes_for(cfg,host):
    if cfg.get('route_type')!=1:raise RuntimeError('此网关要求全局路由，首版暂只支持内网分流')
    if 'routes' in cfg:
        routes=[ipaddress.IPv4Network((r['destination'],r['netmask']),strict=False) for r in cfg['routes']]
    else:routes=[ipaddress.IPv4Network(r) for r in cfg.get('expansion_routes',[])]
    excludes=[ipaddress.IPv4Network(x) for x in cfg.get('exclude_routes',[])]
    excludes.append(ipaddress.IPv4Network(socket.gethostbyname(host)+'/32'))
    if any(r.prefixlen==0 for r in routes):raise RuntimeError('不允许默认路由，请使用内网分流配置')
    for excluded in excludes:
        revised=[]
        for route in routes:
            if route.subnet_of(excluded):continue
            revised.extend(route.address_exclude(excluded) if excluded.subnet_of(route) else [route])
        routes=revised
    return [str(r) for r in ipaddress.collapse_addresses(routes)]

class Session(threading.Thread):
    def __init__(self,profile,password,registry,emit):
        super().__init__(daemon=True,name='vpn-'+profile.id[:8])
        self.profile=profile;self.password=password;self.registry=registry;self.emit_cb=emit
        self.cancel=threading.Event();self.answers=queue.Queue();self.sockets=[]
        self.tx=0;self.rx=0;self.adapter=None
    def emit(self,name,**data):self.emit_cb(self.profile.id,name,data)
    def stop(self):self.cancel.set()
    def answer(self,kind,value):self.answers.put((kind,value))
    def wait(self,kind,timeout=120):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if self.cancel.is_set():raise Cancelled()
            try:
                k,value=self.answers.get(timeout=.2)
                if k==kind:return value
            except queue.Empty:pass
        raise RuntimeError('等待用户输入超时，请重新连接')
    def connect_tls(self):
        s=p.tls_connect(self.profile.host,self.profile.port,self.profile.pin);self.sockets.append(s);return s
    def trust(self):
        if self.profile.pin:return
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((self.profile.host,self.profile.port),timeout=12) as raw:
            with ctx.wrap_socket(raw,server_hostname=self.profile.host) as tls:
                pin=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        self.emit('certificate',fingerprint=pin)
        if self.wait('certificate') is not True:raise Cancelled()
        self.profile.pin=pin;self.emit('pin_saved',fingerprint=pin)
    def run(self):
        sink=p.EVENT_SINK.set(lambda event,fields:self.emit('diagnostic',message=event))
        control=None;token=None;info=None;protocol=None
        try:
            self.emit('state',state='connecting',text='连接网关')
            self.trust();protocol=p.negotiate(self.profile.host,self.profile.port,self.profile.pin)
            if self.cancel.is_set():raise Cancelled()
            auth=self.connect_tls();mac=f'{uuid.getnode():012X}';mac='-'.join(mac[i:i+4] for i in range(0,12,4))
            request=p.legacy_auth_request(self.profile.host,self.profile.username,self.password,mac) if protocol=='legacy' else auth_v1(f'{self.profile.host}:{self.profile.port}',self.profile.username,self.password,mac)
            self.password='';auth.sendall(request);del request
            if protocol=='legacy':
                info=p.legacy_auth_response(auth);uid=struct.unpack_from('!I',info,40)[0]
            else:
                try:token=p.parse_auth(read_frame(auth.recv))
                except p.SmsRequired:
                    self.emit('state',state='sms',text='等待短信验证码');self.emit('sms')
                    code=self.wait('sms');request=p.sms_packet(code);del code
                    auth.sendall(request);del request
                    token=p.parse_auth(read_frame(auth.recv))
                uid=0
            if self.cancel.is_set():raise Cancelled()
            self.emit('state',state='connecting',text='获取内网配置')
            control=self.connect_tls()
            if protocol=='legacy':
                control.sendall(p.legacy_frame(3,user_id=uid));cmd,packet=p.read_legacy_frame(control)
                if cmd!=3:raise RuntimeError('网关未接受地址请求')
                cfg=p.parse_legacy_config(packet);data=control
            else:
                control.sendall(encode_frame(3,token));reply=read_frame(control.recv)
                if reply.command!=3:raise RuntimeError('网关未接受地址请求')
                cfg=parse_vip(reply.payload)
                if cfg['result']!=0:raise RuntimeError('网关拒绝分配地址')
                if cfg.get('tunnel_mode') not in (None,0,1):raise RuntimeError('暂不支持网关要求的 UDP 模式')
                data=self.connect_tls();data.sendall(encode_frame(100,token));reply=read_frame(data.recv)
                if reply.command!=100 or not reply.payload or reply.payload[0]!=0:raise RuntimeError('网关拒绝数据连接')
            routes=routes_for(cfg,self.profile.host);self.registry.acquire(self.profile.id,routes)
            if self.cancel.is_set():raise Cancelled()
            self.emit('state',state='connecting',text='安装系统网卡与路由')
            self.adapter=create_adapter('MultiVPN-'+self.profile.id[:8],cfg['vip'],routes,cfg.get('dns_servers',[]))
            self.emit('connected',vip=cfg['vip'],interface=self.adapter.name,index=self.adapter.index,routes=routes,protocol=protocol)
            self.emit('state',state='connected',text='已连接 · 系统内网路由已就绪')
            self.forward(control,data,protocol,uid,token)
        except Cancelled:pass
        except Exception as exc:self.emit('error',message=str(exc))
        finally:
            self.password=''
            if self.adapter:
                try:self.adapter.close()
                except Exception:self.emit('error',message='网卡清理失败，请检查系统网络设置')
                self.adapter=None
            self.registry.release(self.profile.id)
            if control:
                try:control.sendall(p.legacy_frame(4,user_id=struct.unpack_from('!I',info,40)[0]) if protocol=='legacy' else encode_frame(5,token))
                except Exception:pass
            if info:
                try:p.legacy_logout(self.profile.host,self.profile.port,self.profile.pin,info)
                except Exception:pass
            for sock in self.sockets:
                try:sock.close()
                except Exception:pass
            self.emit('state',state='disconnected',text='已断开');p.EVENT_SINK.reset(sink)
    def forward(self,control,data,protocol,uid,token):
        for sock in set([control,data]):sock.setblocking(False)
        writers={s:TLSWriter(s) for s in set([control,data])}
        buffers={s:bytearray() for s in set([control,data])}
        heartbeat=time.monotonic()+8;stats=time.monotonic();counter=0
        while not self.cancel.is_set():
            for _ in range(32):
                if writers[data].size>=1024*1024:break
                packet=self.adapter.read()
                if packet is None:break
                if not packet or packet[0]>>4!=4:continue
                validate_ipv4(packet)
                writers[data].enqueue(p.legacy_frame(2,packet,uid) if protocol=='legacy' else encode_frame(0x66,bytes(8)+packet));self.tx+=len(packet)
            for writer in writers.values():writer.flush()
            ready,_,_=select.select(list(buffers),[],[],.005)
            for sock in buffers:
                if sock not in ready and not sock.pending():continue
                try:chunk=sock.recv(65536)
                except (TimeoutError,ssl.SSLWantReadError,ssl.SSLWantWriteError,BlockingIOError):continue
                if not chunk:raise RuntimeError('网关关闭连接')
                buf=buffers[sock];buf.extend(chunk)
                while len(buf)>=(16 if protocol=='legacy' else 8):
                    head=16 if protocol=='legacy' else 8
                    if protocol=='legacy':
                        m1,m2,_,cmd,size=struct.unpack_from('!IIIHH',buf)
                        if (m1,m2)!=(0xfefcefbe,0xc192a4d6):raise RuntimeError('无效的数据报头')
                    else:
                        magic,version,cmd,size=struct.unpack_from('!4sBBH',buf)
                        if magic!=b'\xc1\x92\xa4\xd6' or version!=1:raise RuntimeError('无效的新版数据报头')
                    if len(buf)<head+size:break
                    payload=bytes(buf[head:head+size]);del buf[:head+size]
                    if cmd==(2 if protocol=='legacy' else 0x66):
                        packet=payload if protocol=='legacy' else payload[8:]
                        validate_ipv4(packet);self.adapter.write(packet);self.rx+=len(packet)
                    elif cmd==(6 if protocol=='legacy' else 50):raise RuntimeError('网关终止了会话')
            now=time.monotonic()
            if now>=heartbeat:
                counter+=1
                writers[control].enqueue(p.legacy_frame(7,user_id=uid) if protocol=='legacy' else encode_frame(6,token+struct.pack('!I',counter)))
                if protocol=='v1':writers[data].enqueue(encode_frame(0x65))
                heartbeat=now+8
            if now-stats>=1:self.emit('traffic',tx=self.tx,rx=self.rx);stats=now
