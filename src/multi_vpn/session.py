"""Per-session protocol and real OS packet forwarding; no shared tunnel state."""
import hashlib,ipaddress,queue,select,socket,ssl,struct,threading,time,uuid
from . import protocol as p
from .wire import encode_frame,read_frame,FrameReader,parse_vip,auth_v1,validate_ipv4
from .platforms import create_adapter
from .transport import TLSWriter,ReceiveQueue,ReceiveHealth,TunnelReader
from .operations import Cancelled,cancellation,check_cancelled,resolve
from .legacy_udp import LegacyUdp


class GatewayKickout(ConnectionError):
    def __init__(self):
        super().__init__('网关终止了会话（KICKOUT）')


def legacy_exchange(control, uid, command, payload=b''):
    control.sendall(p.legacy_frame(command, payload, uid))
    for _ in range(8):
        reply, frame = p.read_legacy_frame(control)
        if reply == command:
            return frame[16:]
        if reply == 8:
            raise GatewayKickout()
        if reply != 7:
            raise p.ProtocolError(f'旧版网关请求 {command} 收到了意外回复 {reply}')
    raise p.ProtocolError(f'旧版网关未完成请求 {command}')

def routes_for(cfg,host):
    if cfg.get('route_type')!=1:raise RuntimeError('此网关要求全局路由，首版暂只支持内网分流')
    if 'routes' in cfg:
        routes=[ipaddress.IPv4Network((r['destination'],r['netmask']),strict=False) for r in cfg['routes']]
    else:routes=[ipaddress.IPv4Network(r) for r in cfg.get('expansion_routes',[])]
    excludes=[ipaddress.IPv4Network(x) for x in cfg.get('exclude_routes',[])]
    gateway=resolve(host,443,family=socket.AF_INET)[0][4][0]
    excludes.append(ipaddress.IPv4Network(gateway+'/32'))
    if any(r.prefixlen==0 for r in routes):raise RuntimeError('不允许默认路由，请使用内网分流配置')
    for excluded in excludes:
        revised=[]
        for route in routes:
            if route.subnet_of(excluded):continue
            revised.extend(route.address_exclude(excluded) if excluded.subnet_of(route) else [route])
        routes=revised
    return [str(r) for r in ipaddress.collapse_addresses(routes)]

class Session(threading.Thread):
    def __init__(self,profile,password,registry,emit,event_log=None):
        super().__init__(daemon=True,name='vpn-'+profile.id[:8])
        self.profile=profile;self.password=password;self.registry=registry;self.emit_cb=emit
        self.cancel=threading.Event();self.answers=queue.Queue();self.sockets=[]
        self.tx=0;self.rx=0;self.adapter=None
        self.event_log=event_log
        self.run_id=uuid.uuid4().hex
        self.metrics={}
    def emit(self,name,**data):
        data['run_id']=self.run_id
        if name=='traffic' and self.event_log:data['log_dropped']=self.event_log.dropped
        if name=='traffic':self.metrics=data.copy()
        if self.event_log:self.event_log.write(self.profile.id,name,data)
        self.emit_cb(self.profile.id,name,data)
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
        with p.open_tls(self.profile.host,self.profile.port) as tls:
            pin=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        self.emit('certificate',fingerprint=pin)
        if self.wait('certificate') is not True:raise Cancelled()
        self.profile.pin=pin;self.emit('pin_saved',fingerprint=pin)
    def run(self):
        with cancellation(self.cancel):self._run()
    def _run(self):
        sink=p.EVENT_SINK.set(lambda event,fields:self.emit('diagnostic',message=event))
        control=None;token=None;info=None;protocol=None;udp=None;kicked=False
        try:
            check_cancelled()
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
                cfg,control,data,udp=self.open_legacy_tunnel(control,uid)
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
            self.adapter=create_adapter('MultiVPN-'+self.profile.id[:8],cfg['vip'],routes,cfg.get('dns_servers',[]),self.profile.mtu)
            check_cancelled()
            self.emit('connected',vip=cfg['vip'],interface=self.adapter.name,index=self.adapter.index,routes=routes,protocol=protocol,transport='udp' if udp else 'tcp')
            self.emit('state',state='connected',text='已连接 · 系统内网路由已就绪')
            self.forward(control,data,protocol,uid,token,udp)
        except Cancelled:pass
        except GatewayKickout as exc:
            kicked=True
            self.emit('error',message=str(exc),error_type=type(exc).__name__)
        except Exception as exc:self.emit('error',message=str(exc),error_type=type(exc).__name__)
        finally:
            self.password=''
            if self.adapter:
                try:
                    with cancellation(None):self.adapter.close()
                except Exception:self.emit('error',message='网卡清理失败，请检查系统网络设置')
                self.adapter=None
            self.registry.release(self.profile.id)
            if control and not kicked:
                try:control.sendall(p.legacy_frame(4,user_id=struct.unpack_from('!I',info,40)[0]) if protocol=='legacy' else encode_frame(5,token))
                except Exception:pass
            for sock in self.sockets:
                try:sock.close()
                except Exception:pass
            if info and not kicked:
                try:
                    # Logout still releases the gateway session after a user
                    # disconnect. Use fresh bounded setup I/O for cleanup.
                    with cancellation(threading.Event()):
                        p.legacy_logout(self.profile.host,self.profile.port,self.profile.pin,info)
                except Exception:pass
            self.emit('state',state='disconnected',text='已断开');p.EVENT_SINK.reset(sink)

    def open_legacy_tunnel(self, control, uid):
        cfg = self.legacy_config(control, uid)
        if not self.profile.legacy_udp or control.family != socket.AF_INET:
            return cfg, control, control, None
        try:
            udp, data = self.open_legacy_udp(control, uid, cfg['vip'])
            return cfg, control, data, udp
        except GatewayKickout:
            raise
        except (OSError, EOFError, p.ProtocolError) as exc:
            check_cancelled()
            self.emit('diagnostic', message='UDP 协商失败，正在使用当前认证会话建立 TLS 数据通道',
                      error_type=type(exc).__name__)
            # A timed-out exchange may have consumed part of a frame. Open a
            # fresh control stream and reuse the authenticated legacy user ID.
            control.close()
            control = self.connect_tls()
            return self.legacy_config(control, uid), control, control, None

    def legacy_config(self, control, uid):
        payload = legacy_exchange(control, uid, 3)
        return p.parse_legacy_config(p.legacy_frame(3, payload, uid))

    def open_legacy_udp(self, control, uid, vip):
        self.emit('state', state='connecting', text='协商旧版 UDP 隧道')
        # The request capability (4) and selected cipher mode (3) differ.
        capability = struct.pack('!I', 4)
        original_timeout = control.gettimeout()
        control.settimeout(5)
        try:
            reply = legacy_exchange(control, uid, 13, capability)
            if len(reply) < 20 or reply[:4] != struct.pack('!I', 3):
                raise p.ProtocolError('网关未接受旧版 UDP 加密模式')
            port_reply = legacy_exchange(control, uid, 26, capability)
            if len(port_reply) < 2 or port_reply[:2] == b'\0\0':
                raise p.ProtocolError('网关未返回有效的 UDP 端口')
        finally:
            control.settimeout(original_timeout)
        port = struct.unpack_from('!H', port_reply)[0]
        gateway = control.getpeername()[0]
        udp = LegacyUdp(reply[4:20], uid, vip, gateway)
        udp.endpoint = (control.getsockname()[0], (gateway, port))
        sock = udp.open_socket()
        try:
            udp.wait_for_probe(sock)
        except OSError:
            sock.close()
            check_cancelled()
            control.sendall(p.legacy_frame(16, user_id=uid))
            self.emit('diagnostic', message='UDP 探测未通过，当前会话已切回 TLS')
            return None,control
        except BaseException:
            sock.close()
            raise
        self.sockets.append(sock)
        self.emit('diagnostic', message='旧版 UDP 探测成功')
        return udp,sock

    def forward(self,control,data,protocol,uid,token,udp=None):
        sockets=dict.fromkeys((control,data))
        for sock in sockets:sock.setblocking(False)
        udp_sock=data if udp else None
        writers={s:TLSWriter(s,datagrams=s is udp_sock) for s in sockets}
        readers={sock:TunnelReader(protocol) for sock in writers if sock is not udp_sock}
        def has_plaintext(sock):
            return sock is not udp_sock and sock.pending()
        receive_wants_write=set()
        heartbeat=time.monotonic()+8;stats=time.monotonic();counter=0
        pending=ReceiveQueue();health=ReceiveHealth(stats);received=0
        last_gateway=stats;last_udp=stats;last_control=None
        udp_invalid=udp_acks=0
        waitable=getattr(self.adapter,'read_waitable',None)
        acknowledge_read=getattr(self.adapter,'acknowledge_read',None)
        repair_until=None;last_repair=float('-inf');next_probe=0;repair_attempts=0
        wire_tx_closed=wire_frames_closed=closed_backpressure=discarded_tx=wire_rx=0
        fallback_pending=False

        def retire_udp():
            nonlocal wire_tx_closed,wire_frames_closed,closed_backpressure,discarded_tx
            writer=writers.pop(udp_sock)
            wire_tx_closed+=writer.sent_bytes
            wire_frames_closed+=writer.sent_frames
            closed_backpressure+=writer.blocked
            discarded_tx+=writer.size
            udp_sock.close()
            if udp_sock in self.sockets:self.sockets.remove(udp_sock)

        def drive_writer(sock,writer,send):
            nonlocal udp_failure
            try:
                writer.check_timeout()
                if send:writer.flush()
            except OSError as exc:
                if sock is not udp_sock:raise
                udp_failure=type(exc).__name__

        while not self.cancel.is_set():
            udp_failure=None
            delivered=pending.flush(self.adapter)
            self.rx+=delivered
            packets=0
            for _ in range(32 if repair_until is None else 0):
                if writers[data].size>=1024*1024:break
                packet=self.adapter.read()
                if packet is None:break
                packets+=1
                if not packet or packet[0]>>4!=4:continue
                health.sent(time.monotonic())
                if udp:frame=udp.encode(packet)
                else:
                    validate_ipv4(packet)
                    frame=p.legacy_frame(2,packet,uid) if protocol=='legacy' else encode_frame(0x66,bytes(8)+packet)
                writers[data].enqueue(frame);self.tx+=len(packet)
            for sock,writer in writers.items():drive_writer(sock,writer,writer.want is None)
            for reader in readers.values():reader.check_timeout()
            readable=[sock for sock in writers if sock is not data or pending.size<1024*1024]
            read_wait=list(dict.fromkeys(readable+[sock for sock,writer in writers.items() if writer.want=='read']))
            if waitable is not None and repair_until is None and writers[data].size<1024*1024:
                read_wait.append(waitable)
            write_wait=[sock for sock,writer in writers.items() if writer.want=='write' or sock in receive_wants_write]
            busy=(packets==32 and writers[data].want is None
                  or delivered and pending.size
                  or any(writer.size and writer.want is None for writer in writers.values()))
            has_pending=any(has_plaintext(sock) for sock in readable)
            timeout=0 if busy or has_pending or udp_failure else .005 if waitable is None or pending.size else .1
            if read_wait or write_wait:ready,writable,_=select.select(read_wait,write_wait,[],timeout)
            else:self.cancel.wait(timeout);ready=[];writable=[]
            if acknowledge_read and waitable in ready and acknowledge_read() is False:
                waitable=None
            for sock,writer in writers.items():
                retry_read=writer.want=='read' and (sock in ready or has_plaintext(sock))
                retry_write=writer.want=='write' and sock in writable
                if (retry_read or retry_write) and not (sock is udp_sock and udp_failure):drive_writer(sock,writer,True)
            for sock in readable:
                if sock not in ready and not has_plaintext(sock) and not (sock in receive_wants_write and sock in writable):continue
                for batch in range(32 if sock is udp_sock else 4):
                    if sock is udp_sock and udp_failure:break
                    if sock is data and pending.size>=1024*1024:break
                    try:chunk=sock.recv(65536)
                    except ssl.SSLWantWriteError:receive_wants_write.add(sock);break
                    except (TimeoutError,ssl.SSLWantReadError,BlockingIOError):receive_wants_write.discard(sock);break
                    except OSError as exc:
                        if sock is not udp_sock:raise
                        udp_failure=type(exc).__name__;break
                    wire_rx+=len(chunk)
                    if sock is udp_sock:
                        try:packet=udp.decode(chunk)
                        except ValueError:
                            udp_invalid+=1
                            continue
                        last_udp=last_gateway=time.monotonic()
                        if repair_until is not None:
                            repair_until=None
                            self.emit('diagnostic',message='UDP 数据通道已重新建立')
                        if packet is not None:
                            pending.enqueue(packet);received+=len(packet);health.received(last_udp)
                        else:udp_acks+=1
                        continue
                    if not chunk:raise ConnectionError('网关关闭连接')
                    receive_wants_write.discard(sock);last_gateway=time.monotonic()
                    if sock is control:last_control=last_gateway
                    for cmd,payload in readers[sock].feed(chunk):
                        if cmd==(2 if protocol=='legacy' else 0x66) and not udp:
                            packet=payload if protocol=='legacy' else payload[8:]
                            validate_ipv4(packet);pending.enqueue(packet);received+=len(packet);health.received(time.monotonic())
                            if fallback_pending:
                                self.emit('diagnostic',message='切回 TLS 后已收到内网数据')
                                fallback_pending=False
                        elif protocol=='legacy' and cmd==8:raise GatewayKickout()
                        elif protocol=='v1' and cmd==50:raise RuntimeError('网关终止了会话')
                    if not has_plaintext(sock):break
            now=time.monotonic()
            udp_deadline=repair_until if repair_until is not None else last_udp+40
            if udp and (udp_failure or now>=udp_deadline):
                was_repairing=repair_until is not None
                retire_udp()
                udp_sock=None
                if udp.endpoint and not was_repairing and now-last_repair>=60:
                    last_repair=now;repair_attempts+=1
                    try:udp_sock=udp.open_socket()
                    except OSError as exc:udp_failure=type(exc).__name__
                if udp_sock is not None:
                    data=udp_sock;self.sockets.append(data)
                    writers[data]=TLSWriter(data,datagrams=True)
                    repair_until=now+6;next_probe=now
                    self.emit('diagnostic',message='正在重新建立 UDP 数据通道',error_type=udp_failure)
                else:
                    writers[control].enqueue(p.legacy_frame(16,user_id=uid))
                    udp=None;data=control;repair_until=None;fallback_pending=True
                    self.emit('transport_changed',transport='tcp',message='UDP 通道失效，当前会话切回 TLS',error_type=udp_failure)
            if repair_until is not None and now>=next_probe:
                writers[data].enqueue(udp.probe());next_probe=now+2
            state=health.check(now)
            if state:self.emit('state',state=state,text='已发出内网数据，但超过 30 秒未收到内网数据，请检查链路或目标服务' if state=='degraded' else '已恢复接收内网数据 · 系统内网路由已就绪')
            if now>=heartbeat:
                counter+=1
                writers[control].enqueue(p.legacy_frame(7,user_id=uid) if protocol=='legacy' else encode_frame(6,token+struct.pack('!I',counter)))
                if protocol=='v1':writers[data].enqueue(encode_frame(0x65))
                if udp and repair_until is None:writers[data].enqueue(udp.probe())
                heartbeat=now+8
            if now-stats>=1:
                self.emit(
                    'traffic',tx=self.tx,rx=self.rx,received=received,pending_rx=pending.size,
                    rx_backpressure=pending.blocked,
                    tx_backpressure=closed_backpressure+sum(writer.blocked for writer in writers.values()),
                    send_queue=sum(writer.size for writer in writers.values()),
                    last_receive_age=round(now-health.last_receive,3),
                    last_gateway_age=round(now-last_gateway,3),
                    rx_queue_age=round(pending.age,3),
                    tx_queue_age=round(max(writer.age for writer in writers.values()),3),
                    partial_frame_bytes=sum(reader.size for reader in readers.values()),
                    udp_invalid=udp_invalid,udp_acks=udp_acks,udp_repairs=repair_attempts,
                    tunnel_tx_bytes=wire_tx_closed+sum(writer.sent_bytes for writer in writers.values()),
                    tunnel_tx_frames=wire_frames_closed+sum(writer.sent_frames for writer in writers.values()),
                    tunnel_rx_bytes=wire_rx,discarded_tx=discarded_tx,
                    last_control_age=round(now-last_control,3) if last_control is not None else None,
                )
                stats=now
