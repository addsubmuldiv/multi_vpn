"""Independent UniVPN legacy/V1 TLS protocol helpers.

Only a caller-selected gateway is contacted. No vendor binary is invoked.
Credentials and session material are never written to logs.
"""
import argparse,ctypes,getpass,hashlib,ipaddress,json,pathlib,secrets,socket,ssl,struct,time,uuid
from contextlib import ExitStack
from .wire import auth_v1,encode_frame,read_frame,parse_tlvs,parse_vip

from contextvars import ContextVar
EVENT_SINK=ContextVar('vpn_event_sink',default=None)

class ProtocolError(Exception): pass
class SmsRequired(ProtocolError): pass

def event(name, **fields):
    sink=EVENT_SINK.get()
    if sink: sink(name, fields)

def configure_transport(transport):
    transport.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    transport.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
    try:
        if hasattr(socket,'SIO_KEEPALIVE_VALS'):
            transport.ioctl(socket.SIO_KEEPALIVE_VALS,(1,30000,10000))
        else:
            for name,value in (('TCP_KEEPIDLE',30),('TCP_KEEPINTVL',10),('TCP_KEEPCNT',3)):
                option=getattr(socket,name,None)
                if option is not None:transport.setsockopt(socket.IPPROTO_TCP,option,value)
    except OSError:event('optional_keepalive_unavailable')

def tls_connect(host,port,pin,timeout=12,read_timeout=15):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    raw=socket.create_connection((host,port),timeout=timeout)
    try:
        configure_transport(raw)
        tls=ctx.wrap_socket(raw,server_hostname=host)
        if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()!=pin:
            tls.close();raise ProtocolError('Gateway certificate pin mismatch; credentials withheld')
        tls.settimeout(read_timeout)
        event('tls_connected',version=tls.version(),cipher=tls.cipher()[0])
        return tls
    except BaseException:
        raw.close();raise

def parse_auth(frame):
    if frame.command!=1 or len(frame.payload)<8:
        raise ProtocolError('Unexpected authentication response command or size')
    status=struct.unpack_from('!I',frame.payload)[0]
    fields=parse_tlvs(frame.payload[8:])
    token=next((v for k,v in fields if k==3),None)
    methods=[v[0] for k,v in fields if k==2 and len(v)==1]
    event('auth_response',status=status,endpoint_flags=frame.payload[5],field_types=[k for k,v in fields],token_present=token is not None,additional_auth_methods=methods)
    if status==1 and methods==[1]:
        raise SmsRequired('Gateway requires SMS verification on the existing TLS connection')
    if status!=0:
        raise ProtocolError('Gateway did not finish basic authentication; no retries or challenge bypass attempted')
    if frame.payload[5]!=0:
        raise ProtocolError('Endpoint-check policy requires additional implementation')
    if token is None or len(token)!=32:
        raise ProtocolError('Gateway did not return a 32-byte session token')
    return token

def summarize_config(cfg):
    return {k:v for k,v in cfg.items() if k not in {'tlvs','key_material','dns_domain_raw','raw'}}

def sms_packet(code):
    if not code.isascii() or not code.isdigit() or not 4<=len(code)<=10:
        raise ProtocolError('Expected a 4..10 digit SMS verification code')
    # FUN_0040fa40: command 2, 33-byte body, method 1 + code[32].
    return encode_frame(2,b'\x01'+code.encode('ascii').ljust(32,b'\0'))

def exact(tls,n):
    data=bytearray()
    while len(data)<n:
        chunk=tls.recv(n-len(data))
        if not chunk:raise EOFError('stream ended before expected reply')
        data.extend(chunk)
    return bytes(data)

def legacy_frame(command,payload=b'',user_id=0):
    return struct.pack('!IIIHH',0xfefcefbe,0xc192a4d6,user_id,command,len(payload))+payload

def negotiate(host,port,pin):
    # Official SITE request always starts in the legacy-compatible envelope.
    body=b'Windows64'.ljust(64,b'\0')+host.encode('ascii').ljust(256,b'\0')+b'\0\x01\0\0'
    with tls_connect(host,port,pin) as tls:
        tls.sendall(legacy_frame(29,body))
        magic=exact(tls,4)
        if magic==bytes.fromhex('c192a4d6'):
            version,cmd,size=struct.unpack('!BBH',exact(tls,4))
            data=exact(tls,size)
            if version!=1 or cmd!=0:raise ProtocolError('Unexpected V1 SITE response')
            event('site_negotiated',protocol='v1',payload_bytes=len(data))
            return 'v1'
        if magic==bytes.fromhex('fefcefbe'):
            second,user,cmd,size=struct.unpack('!IIHH',exact(tls,12))
            data=exact(tls,size)
            if second!=0xc192a4d6 or cmd!=29:raise ProtocolError('Unexpected legacy SITE response')
            event('site_negotiated',protocol='legacy',payload_bytes=len(data))
            return 'legacy'
        raise ProtocolError('Unrecognized SITE response')

def narrow_escape(text):
    return text.replace('%','%25').replace('&','%26').replace('+','%2B')

def legacy_auth_request(host,username,password,mac):
    path='/netextension/netextensionlogin.html?SelectLanguage=0&'
    path+='UserName='+narrow_escape(username)+'&Password='+narrow_escape(password)
    path+='&MacAddress='+mac+'&SVN_Seco_AaA=1'
    # Compatibility header values are from the inspected auth constructor.
    return ('GET '+path+' HTTP/1.1\r\n'
            'Accept: */*\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\n'
            'User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)'
            'OS=Windows64\r\nHost: '+host+'\r\n\r\n').encode('ascii')

def legacy_auth_response(tls):
    if exact(tls,4)!=b'\xf0'*4:raise ProtocolError('Unrecognized legacy auth reply')
    data=bytearray(exact(tls,60))
    tls.settimeout(0.5)
    try:
        while len(data)<4096:
            more=tls.recv(4096-len(data))
            if not more:break
            data.extend(more)
    except (TimeoutError,ssl.SSLError):pass
    finally:tls.settimeout(15)
    status=struct.unpack_from('!i',data)[0]
    event('legacy_auth_response',accepted=status>=0,rejection_code=status if status<0 else None,payload_bytes=len(data),
          gateway_hostid=struct.unpack_from('!I',data,0x14)[0],
          user_hostid=struct.unpack_from('!I',data,0x18)[0],
          endpoint_check=struct.unpack_from('!I',data,0x1c)[0])
    if status<0:raise ProtocolError('Legacy authentication did not finish successfully; not retried')
    if struct.unpack_from('!I',data,0x18)[0]==1:
        raise ProtocolError('Gateway requests host-ID authentication; unsupported')
    if struct.unpack_from('!I',data,0x1c)[0]!=0:
        raise ProtocolError('Gateway requests endpoint checks; unsupported')
    return bytes(data)

def read_legacy_frame(tls):
    head=exact(tls,16)
    m1,m2,user,cmd,size=struct.unpack('!IIIHH',head)
    if (m1,m2)!=(0xfefcefbe,0xc192a4d6):raise ProtocolError('Invalid legacy tunnel header')
    return cmd,head+exact(tls,size)

def parse_legacy_config(packet):
    packet=bytes(packet)
    if len(packet)<204:raise ProtocolError('Truncated legacy network configuration')
    def u32(off):return struct.unpack_from('!I',packet,off)[0]
    def ip(off):return str(ipaddress.IPv4Address(packet[off:off+4]))
    count=u32(200)
    if count>1024 or len(packet)<204+count*12:raise ProtocolError('Invalid legacy route list length')
    cfg=dict(vip=ip(16),netmask=ip(20),allocation_type=u32(24),route_type=u32(36),
             dns_servers=[ip(i) for i in (176,180,184) if u32(i)],routes=[])
    for i in range(count):
        off=204+i*12
        cfg['routes'].append({'destination':ip(off),'netmask':ip(off+4),'port':u32(off+8)})
    if cfg['vip'] in ('0.0.0.0','255.255.255.255'):raise ProtocolError('Gateway did not assign a valid IPv4 address')
    return cfg

def legacy_logout(host,port,pin,info):
    vt,session=struct.unpack_from('!II',info,4)
    user=struct.unpack_from('!I',info,40)[0]
    cookie=info[84:148].split(b'\0',1)[0]
    # Only the current experiment's returned identifiers are used.
    if any(c in cookie for c in (b'\r',b'\n')):raise ProtocolError('Invalid session cookie')
    path=f'/logout.html?VTID={vt}&UserID={user}&SessionID={session}&SelectLanguage=2&'
    req=('GET '+path+' HTTP/1.1\r\nHost: '+host+'\r\nCookie: SVN_SessionID=').encode('ascii')+cookie+b'\r\n\r\n'
    with tls_connect(host,port,pin,timeout=3,read_timeout=3) as s:
        s.sendall(req)
        reply=s.recv(2048)
        status=reply.split(b'\r\n',1)[0].decode('ascii','replace') if reply.startswith(b'HTTP/') else 'non-HTTP reply'
        event('auth_logout',reply_bytes=len(reply),response_status=status)
