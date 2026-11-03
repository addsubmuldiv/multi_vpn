"""Resources and explicit relaunch arguments for installed/frozen builds."""
from pathlib import Path
import json,os,shlex,subprocess,sys

def resource_root():
    return Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parents[2]))

def relaunch_args(data_dir):
    prefix=[] if getattr(sys,'frozen',False) else ['-m','multi_vpn']
    return prefix+['--data-dir',str(Path(data_dir).resolve())]

def launch_macos_admin(data_dir):
    """Use the system authorization dialog; never collect a system password."""
    data_dir=Path(data_dir).resolve();data_dir.mkdir(parents=True,exist_ok=True)
    args=[sys.executable,*relaunch_args(data_dir)]
    command=f'nohup {shlex.join(args)} </dev/null >{shlex.quote(str(data_dir / "startup.log"))} 2>&1 &'
    result=subprocess.run(['/usr/bin/osascript','-e',
                           'do shell script '+json.dumps(command)+' with administrator privileges'],
                          capture_output=True,text=True)
    if result.returncode:raise RuntimeError('未取得管理员授权，连接需要创建系统网卡。')

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
        QTimer.singleShot(100,app.quit);app.exec();window.close();app.processEvents()
    if previous is None:os.environ.pop('MULTIVPN_DATA_DIR',None)
    else:os.environ['MULTIVPN_DATA_DIR']=previous
    if report:
        import ctypes
        Path(report).write_text(json.dumps({'gui_started':True,'admin':bool(ctypes.windll.shell32.IsUserAnAdmin())}),encoding='utf-8')
    return 0
