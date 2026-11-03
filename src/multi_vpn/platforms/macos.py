"""Native utun backend. Requires root; no third-party kernel driver."""
import ctypes,fcntl,ipaddress,os,select,socket,struct,subprocess

class MacAdapter:
    def __init__(self,name,vip,routes,dns=()):
        self.sock=None;self.routes=[];self.name='';self.index=None
        if os.geteuid()!=0:raise RuntimeError('macOS 系统网卡需要 root 权限，请通过管理员启动脚本运行')
        # No global DNS mutation; IP access is the initial supported workflow.
        try:
            self.sock=socket.socket(32,socket.SOCK_DGRAM,2)
            info=bytearray(struct.pack('I96s',0,b'com.apple.net.utun_control'))
            fcntl.ioctl(self.sock,0xc0644e03,info,True)
            control_id=struct.unpack_from('I',info)[0]
            addr=struct.pack('BBHII5I',32,32,2,control_id,0,0,0,0,0,0)
            libc=ctypes.CDLL(None,use_errno=True);libc.connect.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
            if libc.connect(self.sock.fileno(),addr,len(addr))!=0:raise OSError(ctypes.get_errno(),'utun connect failed')
            self.name=self.sock.getsockopt(2,2,64).split(b'\0')[0].decode()
            self.index=socket.if_nametoindex(self.name)
            vip=str(ipaddress.IPv4Address(vip))
            subprocess.run(['/sbin/ifconfig',self.name,'inet',vip,vip,'netmask','255.255.255.255','mtu','1400','up'],check=True,capture_output=True)
            for route in routes:
                route=str(ipaddress.IPv4Network(route))
                subprocess.run(['/sbin/route','-n','add','-net',route,'-interface',self.name],check=True,capture_output=True)
                self.routes.append(route)
            self.sock.setblocking(False)
        except BaseException:self.close();raise
    def read(self):
        try:return self.sock.recv(65539)[4:]
        except BlockingIOError:return None
    def write(self,packet):self.sock.send(struct.pack('!I',socket.AF_INET)+packet)
    def close(self):
        for route in reversed(self.routes):
            subprocess.run(['/sbin/route','-n','delete','-net',route,'-interface',self.name],capture_output=True)
        self.routes=[]
        if self.sock:self.sock.close();self.sock=None
