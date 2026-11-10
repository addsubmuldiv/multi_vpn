"""Resources and explicit relaunch arguments for installed/frozen builds."""
from pathlib import Path
import array,json,os,shlex,socket,struct,subprocess,sys,tempfile,time
from .operations import check_cancelled,CancellableSocket

def _send_helper_message(connection,message,fd=None):
    payload=json.dumps(message,separators=(',',':')).encode('utf-8')
    packet=struct.pack('!I',len(payload))+payload
    ancillary=[] if fd is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]
    sent=connection.sendmsg([packet],ancillary)
    if sent<len(packet):connection.sendall(packet[sent:])

def _receive_helper_message(connection):
    header,ancillary,_,_=connection.recvmsg(4,socket.CMSG_SPACE(array.array('i').itemsize))
    fds=array.array('i')
    for level,kind,data in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
            fds.frombytes(data[:len(data)-len(data)%fds.itemsize])
    try:
        while len(header)<4:
            chunk=connection.recv(4-len(header))
            if not chunk:raise RuntimeError('管理员辅助进程已断开')
            header+=chunk
        size=struct.unpack('!I',header)[0]
        if size>8192:raise RuntimeError('管理员辅助进程返回数据过大')
        chunks=[];received=0
        while received<size:
            chunk=connection.recv(size-received)
            if not chunk:raise RuntimeError('管理员辅助进程已断开')
            chunks.append(chunk);received+=len(chunk)
        return json.loads(b''.join(chunks)),fds
    except BaseException:
        for fd in fds:os.close(fd)
        raise

def macos_privileged_adapter(vip,routes):
    check_cancelled()
    prefix=[] if getattr(sys,'frozen',False) else ['-m','multi_vpn']
    helper=shlex.join([sys.executable,*prefix,'--network-helper'])
    if not getattr(sys,'frozen',False):
        helper='/usr/bin/env PYTHONPATH='+shlex.quote(str(Path(__file__).resolve().parent.parent))+' '+helper
    process=None;control=None;fds=array.array('i')
    with tempfile.TemporaryDirectory(prefix='mvpn-') as directory:
        path=str(Path(directory)/'helper.sock')
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            listener.bind(path);os.chmod(path,0o600);listener.listen(1);listener.settimeout(.2)
            request=json.dumps({'socket':path,'vip':vip,'routes':routes},separators=(',',':'))
            command=f'printf %s {shlex.quote(request)} | {helper}'
            script='do shell script '+json.dumps(command)+' with administrator privileges'
            process=subprocess.Popen(['/usr/bin/osascript','-e',script],stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+180
            while True:
                check_cancelled()
                try:control,_=listener.accept();break
                except socket.timeout:
                    if process.poll() is not None:raise RuntimeError('未取得管理员授权或辅助进程未能启动')
                    if time.monotonic()>=deadline:raise RuntimeError('等待管理员授权超时')
            control=CancellableSocket(control,30)
            response,fds=_receive_helper_message(control)
            if response.get('error'):raise RuntimeError(response['error'])
            if not fds:raise RuntimeError('管理员辅助进程未返回 utun 网卡')
            fd=fds.pop(0)
            for extra in fds:os.close(extra)
            return response,fd,control,process
        except BaseException:
            if control:control.close()
            for fd in fds:
                try:os.close(fd)
                except OSError:pass
            if process:
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:process.wait(timeout=2)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
            raise
        finally:listener.close()

def run_macos_network_helper():
    control=None;tun=None;name='';routes=[]
    try:
        chunks=[];size=0
        while size<=65536:
            chunk=os.read(0,min(4096,65537-size))
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
        raw=b''.join(chunks)
        if len(raw)>65536:raise ValueError('request too large')
        request=json.loads(raw)
        path=request.get('socket')
        if not isinstance(path,str) or not path.startswith('/') or len(path.encode())>=104:
            raise ValueError('invalid socket path')
        if not isinstance(request.get('routes'),list) or len(request['routes'])>256:
            raise ValueError('invalid route list')
        control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);control.connect(path)
        from .platforms.macos import create_root_adapter,close_root_adapter
        tun,name,index,routes=create_root_adapter(request.get('vip'),request['routes'])
        _send_helper_message(control,{'name':name,'index':index},tun.fileno())
        while control.recv(1):pass
        return 0
    except Exception as exc:
        if control:
            try:_send_helper_message(control,{'error':str(exc)})
            except OSError:pass
        return 1
    finally:
        if tun:
            try:close_root_adapter(tun,name,routes)
            except Exception:pass
        if control:control.close()

def resource_root():
    return Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parents[2]))

def relaunch_args(data_dir):
    prefix=[]
    if not getattr(sys,'frozen',False):
        # Windows elevation can start with a fresh environment. Preserve the
        # checkout explicitly so Python cannot pick up a different installation.
        source=str(Path(__file__).resolve().parent.parent)
        bootstrap=f"import runpy,sys; sys.path.insert(0,{source!r}); runpy.run_module('multi_vpn',run_name='__main__',alter_sys=True)"
        prefix=['-c',bootstrap]
    return prefix+['--data-dir',str(Path(data_dir).resolve())]

def frozen_self_test(report=None):
    from PySide6.QtWidgets import QApplication
    from . import wire,protocol,session
    import keyring
    root=resource_root()
    if not (root/'assets/icon.png').is_file():raise RuntimeError('Missing bundled icon')
    if sys.platform=='win32':
        import ctypes
        library=ctypes.WinDLL(str(root/'vendor/wintun.dll'))
        assert library.WintunCreateAdapter
        import keyring.backends.Windows
    elif sys.platform=='darwin':
        from .platforms import macos
        import keyring.backends.macOS
    import tempfile
    from PySide6.QtCore import QTimer
    from .app import Window
    previous=os.environ.get('MULTIVPN_DATA_DIR')
    with tempfile.TemporaryDirectory(prefix='multivpn-test-') as directory:
        os.environ['MULTIVPN_DATA_DIR']=directory
        app=QApplication.instance() or QApplication([])
        window=Window();window.show();app.processEvents()
        assert window.isVisible() and window.list.count()==0
        QTimer.singleShot(100,window.request_exit);app.exec();window.request_exit();app.processEvents()
    if previous is None:os.environ.pop('MULTIVPN_DATA_DIR',None)
    else:os.environ['MULTIVPN_DATA_DIR']=previous
    if report:
        import ctypes
        Path(report).write_text(json.dumps({'gui_started':True,'admin':bool(ctypes.windll.shell32.IsUserAnAdmin())}),encoding='utf-8')
    return 0
