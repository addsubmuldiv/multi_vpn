"""Wintun integration. All mutations are restricted to our newly created adapter."""
import ctypes as c
from ctypes import wintypes as w
import ipaddress,json,pathlib,socket,subprocess,sys,threading
from ..operations import run_process
from . import validate_mtu

def powershell(command):
    result=run_process(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                           "$ErrorActionPreference='Stop';"+command],capture_output=True,
                          text=True,encoding='utf-8',errors='replace',timeout=45,
                          creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise RuntimeError(result.stderr.strip() or 'Windows 网络配置失败')
    return result.stdout.strip()

def address_ready_script(index,vip,timeout=30):
    """Check the assigned address, not unrelated APIPA/secondary addresses.

    PowerShell comparison operators filter arrays. With the old code a list
    containing Preferred AND Tentative passed the loop then failed the final
    '-ne Preferred' check. Keep the selected address and its state scalar.
    """
    index=int(index);vip=str(ipaddress.IPv4Address(vip));timeout=max(0,int(timeout))
    return f"""
$deadline=(Get-Date).AddSeconds({timeout})
$ready=$false
$state='Missing'
do {{
    $target=Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 -IPAddress '{vip}' -ErrorAction SilentlyContinue |
        Where-Object {{ $_.IPAddress -eq '{vip}' }} | Select-Object -First 1
    $state=if($null -eq $target){{'Missing'}}else{{[string]$target.AddressState}}
    if($state -eq 'Preferred'){{ $ready=$true; break }}
    if($state -eq 'Duplicate' -or (Get-Date) -ge $deadline){{ break }}
    Start-Sleep -Milliseconds 200
}} while($true)
@{{ready=$ready;state=$state}} | ConvertTo-Json -Compress
"""

def require_address_ready(result,vip):
    status=json.loads(result)
    if status.get('ready') is True and status.get('state')=='Preferred':return
    state=status.get('state','Unknown')
    label={'Duplicate':'地址冲突','Tentative':'仍在确认地址','Invalid':'地址无效',
           'Missing':'未找到网关分配的地址','Deprecated':'地址已弃用'}.get(state,state)
    raise RuntimeError(f'虚拟 IP {vip} 尚未就绪：{label}。请检查网卡状态及是否存在重复地址；现有其他连接未被修改。')

class PacketWakeup:
    """Bridge a Wintun wait handle into the socket readiness loop."""
    def __init__(self, packet_event):
        self.kernel=c.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateEventW.argtypes=[c.c_void_p,w.BOOL,w.BOOL,w.LPCWSTR]
        self.kernel.CreateEventW.restype=w.HANDLE
        self.kernel.SetEvent.argtypes=[w.HANDLE]
        self.kernel.CloseHandle.argtypes=[w.HANDLE]
        self.kernel.WaitForMultipleObjects.argtypes=[w.DWORD,c.POINTER(w.HANDLE),w.BOOL,w.DWORD]
        self.kernel.WaitForMultipleObjects.restype=w.DWORD
        self.stop=self.kernel.CreateEventW(None,True,False,None)
        if not self.stop:raise c.WinError(c.get_last_error())
        self.reader=self.writer=None
        try:
            self.reader,self.writer=socket.socketpair()
            self.reader.setblocking(False)
            self.events=(w.HANDLE*2)(self.stop,packet_event)
            self.thread=threading.Thread(target=self.run,daemon=True,name='vpn-wintun-wake')
            self.thread.start()
        except BaseException:
            for sock in (self.reader,self.writer):
                if sock:sock.close()
            self.kernel.CloseHandle(self.stop)
            raise
    def run(self):
        with self.writer:
            try:
                while self.kernel.WaitForMultipleObjects(2,self.events,False,0xffffffff)==1:
                    self.writer.sendall(b'\1')
                    if not self.writer.recv(1):break
            except OSError:pass
    def acknowledge(self):
        if not self.reader.recv(1):raise ConnectionError('Wintun 唤醒线程已退出')
        self.reader.send(b'\1')
    def close(self):
        self.kernel.SetEvent(self.stop)
        try:self.reader.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.reader.close()
        self.thread.join()
        self.kernel.CloseHandle(self.stop)


class WindowsAdapter:
    def __init__(self,name,vip,routes,dns=(),mtu=1400):
        self.handle=None;self.session=None;self.index=None;self.wakeup=None
        mtu=validate_mtu(mtu)
        if not c.windll.shell32.IsUserAnAdmin():raise RuntimeError('创建系统网卡需要管理员权限，请以管理员身份运行')
        root=pathlib.Path(getattr(sys,'_MEIPASS',pathlib.Path(__file__).resolve().parents[3]))
        dll=root/'vendor'/'wintun.dll'
        if not dll.is_file():raise RuntimeError('缺少 Wintun，请运行 scripts/install_wintun.py')
        self.dll=c.WinDLL(str(dll),use_last_error=True)
        defs={
            'WintunCreateAdapter':([w.LPCWSTR,w.LPCWSTR,c.c_void_p],c.c_void_p),
            'WintunCloseAdapter':([c.c_void_p],None),
            'WintunGetAdapterLUID':([c.c_void_p,c.POINTER(c.c_uint64)],None),
            'WintunStartSession':([c.c_void_p,w.DWORD],c.c_void_p),
            'WintunEndSession':([c.c_void_p],None),
            'WintunGetReadWaitEvent':([c.c_void_p],w.HANDLE),
            'WintunReceivePacket':([c.c_void_p,c.POINTER(w.DWORD)],c.c_void_p),
            'WintunReleaseReceivePacket':([c.c_void_p,c.c_void_p],None),
            'WintunAllocateSendPacket':([c.c_void_p,w.DWORD],c.c_void_p),
            'WintunSendPacket':([c.c_void_p,c.c_void_p],None)}
        for key,(args,result) in defs.items():
            f=getattr(self.dll,key);f.argtypes=args;f.restype=result
        try:
            self.handle=self.dll.WintunCreateAdapter(name,'MultiVPN',None)
            if not self.handle:raise c.WinError(c.get_last_error())
            luid=c.c_uint64();self.dll.WintunGetAdapterLUID(self.handle,c.byref(luid))
            index=w.ULONG();api=c.WinDLL('iphlpapi');api.ConvertInterfaceLuidToIndex.argtypes=[c.POINTER(c.c_uint64),c.POINTER(w.ULONG)]
            error=api.ConvertInterfaceLuidToIndex(c.byref(luid),c.byref(index))
            if error:raise c.WinError(error)
            self.index=index.value;self.name=name
            self.session=self.dll.WintunStartSession(self.handle,0x400000)
            if not self.session:raise c.WinError(c.get_last_error())
            vip=str(ipaddress.IPv4Address(vip))
            commands=[f'Set-NetIPInterface -InterfaceIndex {self.index} -AddressFamily IPv4 -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 1',
                      f"New-NetIPAddress -InterfaceIndex {self.index} -IPAddress '{vip}' -PrefixLength 32 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null",
                      f'Set-NetIPInterface -InterfaceIndex {self.index} -AddressFamily IPv4 -NlMtuBytes {mtu}']
            for route in routes:
                route=str(ipaddress.IPv4Network(route))
                commands.append(f"New-NetRoute -DestinationPrefix '{route}' -InterfaceIndex {self.index} -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null")
            if dns:
                servers=','.join("'"+str(ipaddress.IPv4Address(x))+"'" for x in dns)
                commands.append(f'Set-DnsClientServerAddress -InterfaceIndex {self.index} -ServerAddresses @({servers})')
            commands.append(address_ready_script(self.index,vip))
            require_address_ready(powershell(';'.join(commands)),vip)
            packet_event=self.dll.WintunGetReadWaitEvent(self.session)
            if packet_event:
                try:self.wakeup=PacketWakeup(packet_event)
                except OSError:pass
        except BaseException:
            self.close();raise
    def read(self):
        size=w.DWORD();p=self.dll.WintunReceivePacket(self.session,c.byref(size))
        if not p:
            error=c.get_last_error()
            if error==259:return None
            raise c.WinError(error)
        try:return c.string_at(p,size.value)
        finally:self.dll.WintunReleaseReceivePacket(self.session,p)
    def write(self,packet):
        p=self.dll.WintunAllocateSendPacket(self.session,len(packet))
        if not p:
            if c.get_last_error()==111:return False
            raise c.WinError(c.get_last_error())
        c.memmove(p,packet,len(packet));self.dll.WintunSendPacket(self.session,p);return True
    @property
    def read_waitable(self):return self.wakeup.reader if self.wakeup else None
    def acknowledge_read(self):
        try:self.wakeup.acknowledge()
        except OSError:
            self.wakeup.close();self.wakeup=None
            return False
    def close(self):
        if self.wakeup:self.wakeup.close();self.wakeup=None
        if self.session:self.dll.WintunEndSession(self.session);self.session=None
        if self.handle:self.dll.WintunCloseAdapter(self.handle);self.handle=None
