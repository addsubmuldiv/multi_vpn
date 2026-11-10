"""Native utun backend. Requires a privileged helper; no third-party kernel driver."""
import ctypes,fcntl,ipaddress,os,socket,struct,subprocess
from ..operations import run_process
from . import validate_mtu

def create_root_adapter(vip,routes,mtu=1400):
    if os.geteuid()!=0:raise RuntimeError('macOS 系统网卡需要管理员权限')
    mtu=validate_mtu(mtu)
    sock=socket.socket(32,socket.SOCK_DGRAM,2);name='';added=[]
    try:
        info=bytearray(struct.pack('I96s',0,b'com.apple.net.utun_control'))
        fcntl.ioctl(sock,0xc0644e03,info,True)
        control_id=struct.unpack_from('I',info)[0]
        addr=struct.pack('BBHII5I',32,32,2,control_id,0,0,0,0,0,0)
        libc=ctypes.CDLL(None,use_errno=True);libc.connect.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
        if libc.connect(sock.fileno(),addr,len(addr))!=0:raise OSError(ctypes.get_errno(),'utun connect failed')
        name=sock.getsockopt(2,2,64).split(b'\0')[0].decode()
        index=socket.if_nametoindex(name);vip=str(ipaddress.IPv4Address(vip))
        run_process(['/sbin/ifconfig',name,'inet',vip,vip,'netmask','255.255.255.255','mtu',str(mtu),'up'],timeout=10,check=True,capture_output=True)
        for route in routes:
            route=str(ipaddress.IPv4Network(route))
            run_process(['/sbin/route','-n','add','-net',route,'-interface',name],timeout=10,check=True,capture_output=True)
            added.append(route)
        sock.setblocking(False)
        return sock,name,index,added
    except BaseException:
        try:close_root_adapter(sock,name,added)
        except Exception:pass
        raise

def close_root_adapter(sock,name,routes):
    error=None
    try:
        for route in reversed(routes):
            try:
                subprocess.run(['/sbin/route','-n','delete','-net',route,'-interface',name],capture_output=True,timeout=10)
            except Exception as exc:error=exc
    finally:sock.close()
    if error:raise error

class MacAdapter:
    def __init__(self,name,vip,routes,dns=(),mtu=1400):
        from ..runtime import macos_privileged_adapter
        self.sock=None;self.control=None;self.helper=None;self.name='';self.index=None
        result,fd,self.control,self.helper=macos_privileged_adapter(vip,routes,mtu)
        try:
            self.sock=socket.socket(32,socket.SOCK_DGRAM,2,fileno=fd)
            self.sock.setblocking(False)
            self.name=result['name'];self.index=result['index']
        except BaseException:
            if self.sock is None:os.close(fd)
            self.close();raise
    def read(self):
        try:return self.sock.recv(65539)[4:]
        except BlockingIOError:return None
    @property
    def read_waitable(self):return self.sock
    def write(self,packet):self.sock.send(struct.pack('!I',socket.AF_INET)+packet)
    def close(self):
        if self.sock:self.sock.close();self.sock=None
        if self.control:self.control.close();self.control=None
        if self.helper:
            try:self.helper.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.helper.terminate()
                try:self.helper.wait(timeout=2)
                except subprocess.TimeoutExpired:self.helper.kill();self.helper.wait()
            self.helper=None
