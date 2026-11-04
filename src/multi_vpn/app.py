import ctypes,dataclasses,os,sys,time
from PySide6.QtCore import Qt,Signal,QObject,QTimer
from PySide6.QtWidgets import (QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QListWidget,
    QPushButton,QLabel,QLineEdit,QSpinBox,QDialog,QDialogButtonBox,QFormLayout,QMessageBox,
    QPlainTextEdit,QInputDialog,QCheckBox,QSplitter)
from .model import Profile,Store,RouteRegistry
from .session import Session
from .runtime import resource_root,relaunch_args
from . import __version__
from .diagnostics import EventLog

class Signals(QObject):
    message=Signal(str,str,dict)

class ProfileDialog(QDialog):
    def __init__(self,profile,password,parent):
        super().__init__(parent);self.setWindowTitle('连接配置');self.resize(450,330)
        self.profile=dataclasses.replace(profile);layout=QFormLayout(self)
        self.name=QLineEdit(profile.name);self.host=QLineEdit(profile.host)
        self.port=QSpinBox();self.port.setRange(1,65535);self.port.setValue(profile.port)
        self.username=QLineEdit(profile.username);self.password=QLineEdit(password);self.password.setEchoMode(QLineEdit.Password)
        self.remember=QCheckBox('在系统凭据库中保存密码');self.remember.setChecked(bool(password))
        if sys.platform=='darwin' and os.geteuid()==0:
            self.remember.setChecked(False);self.remember.setEnabled(False)
            self.remember.setText('本版 macOS 密码仅保留在本次连接中')
        for title,w in [('名称',self.name),('VPN 网关',self.host),('端口',self.port),('账号',self.username),('密码',self.password)]:layout.addRow(title,w)
        layout.addRow(self.remember)
        self.buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept);self.buttons.rejected.connect(self.reject);layout.addRow(self.buttons)
    def accept(self):
        if not self.host.text().strip() or not self.username.text().strip():
            QMessageBox.warning(self,'配置不完整','请填写网关和账号');return
        if any(c in self.host.text() for c in '\r\n /\\'):
            QMessageBox.warning(self,'网关格式','请仅填写 IP 或域名，端口单独填写');return
        if self.profile.host!=self.host.text().strip() or self.profile.port!=self.port.value():self.profile.pin=''
        self.profile.name=self.name.text().strip() or self.host.text().strip()
        self.profile.host=self.host.text().strip();self.profile.port=self.port.value();self.profile.username=self.username.text().strip()
        super().accept()

class Window(QMainWindow):
    def __init__(self):
        super().__init__();self.setWindowTitle('Multi VPN · '+__version__);self.resize(1020,690)
        self.store=Store();self.profiles=self.store.load();self.sessions={};self.states={};self.details={};self.memory_passwords={}
        self.event_log=EventLog(self.store.path.parent/'logs')
        self.registry=RouteRegistry();self.signals=Signals();self.signals.message.connect(self.message)
        self._closing=False;root=QWidget();self.setCentralWidget(root);outer=QVBoxLayout(root)
        title=QLabel('Multi VPN');title.setObjectName('title');outer.addWidget(title)
        outer.addWidget(QLabel('多个独立连接 · 系统内网访问'))
        self.permission=QLabel();outer.addWidget(self.permission)
        if sys.platform=='win32' and not ctypes.windll.shell32.IsUserAnAdmin():
            self.permission.setText('创建系统网卡需要管理员权限。')
            elevate=QPushButton('以管理员身份重新启动');elevate.clicked.connect(self.elevate);outer.addWidget(elevate)
        elif sys.platform=='darwin' and os.geteuid()!=0:self.permission.setText('请通过项目的 macOS 管理员启动脚本运行，以创建系统 utun 网卡。')
        split=QSplitter();outer.addWidget(split,1)
        left=QWidget();ll=QVBoxLayout(left);self.list=QListWidget();self.list.currentRowChanged.connect(self.refresh);ll.addWidget(self.list)
        actions=QHBoxLayout();ll.addLayout(actions)
        for label,fn in [('新增',self.add),('编辑',self.edit),('删除',self.delete)]:
            b=QPushButton(label);b.clicked.connect(fn);actions.addWidget(b)
        duplicate=QPushButton('复制配置');duplicate.clicked.connect(self.duplicate);ll.addWidget(duplicate)
        right=QWidget();rl=QVBoxLayout(right);self.heading=QLabel('选择或新增连接');self.heading.setObjectName('heading');rl.addWidget(self.heading)
        self.status=QLabel('未连接');rl.addWidget(self.status)
        self.info=QLabel('');self.info.setWordWrap(True);self.info.setTextInteractionFlags(Qt.TextSelectableByMouse);rl.addWidget(self.info)
        self.traffic=QLabel('发送 0 B / 接收 0 B');self.traffic.setWordWrap(True);rl.addWidget(self.traffic)
        buttons=QHBoxLayout();rl.addLayout(buttons)
        self.connect_button=QPushButton('连接');self.connect_button.setObjectName('primary');self.connect_button.clicked.connect(self.connect_selected);buttons.addWidget(self.connect_button)
        self.disconnect_button=QPushButton('断开');self.disconnect_button.clicked.connect(self.disconnect_selected);buttons.addWidget(self.disconnect_button)
        rl.addWidget(QLabel('连接日志'));self.logs=QPlainTextEdit();self.logs.setReadOnly(True);self.logs.setMaximumBlockCount(500);rl.addWidget(self.logs,1)
        log_location=QLabel('诊断日志：'+str(self.event_log.path) if self.event_log.handler else '诊断日志无法写入，请检查配置目录权限')
        log_location.setTextInteractionFlags(Qt.TextSelectableByMouse);log_location.setWordWrap(True);rl.addWidget(log_location)
        split.addWidget(left);split.addWidget(right);split.setSizes([310,710])
        self.log_lines={};self.populate()
        self.timer=QTimer(self);self.timer.timeout.connect(self.refresh);self.timer.start(1000)
    def current(self):
        i=self.list.currentRow();return self.profiles[i] if 0<=i<len(self.profiles) else None
    def running(self,p):return p and p.id in self.sessions and self.sessions[p.id].is_alive()
    def populate(self):
        i=self.list.currentRow();self.list.clear()
        for p in self.profiles:self.list.addItem(p.name)
        self.list.setCurrentRow(max(0,min(i,len(self.profiles)-1)));self.refresh()
    def refresh(self):
        p=self.current();active=self.running(p)
        self.connect_button.setEnabled(bool(p) and not active);self.disconnect_button.setEnabled(bool(active))
        for i,profile in enumerate(self.profiles):
            state=self.states.get(profile.id,('disconnected','已断开'))
            self.list.item(i).setText(profile.name+'  ·  '+state[1])
        if not p:return
        self.heading.setText(p.name);self.status.setText(self.states.get(p.id,('','已断开'))[1])
        d=self.details.get(p.id,{})
        text=f'网关：{p.host}:{p.port}\n账号：{p.username}'
        if d:text+=f"\n虚拟 IP：{d['vip']}\n系统网卡：{d['interface']}\n内网路由："+', '.join(d['routes'])
        self.info.setText(text);self.logs.setPlainText('\n'.join(self.log_lines.get(p.id,[])))
        cursor=self.logs.textCursor();cursor.movePosition(cursor.MoveOperation.End);self.logs.setTextCursor(cursor)
        s=self.sessions.get(p.id);self.traffic.setText(f'发送 {s.tx:,} B / 接收 {s.rx:,} B' if s else '发送 0 B / 接收 0 B')
        if s and s.metrics:
            self.traffic.setText(self.traffic.text()+f"\n发送排队 {s.metrics.get('send_queue',0):,} B / 接收排队 {s.metrics.get('pending_rx',0):,} B / 网卡重试 {s.metrics.get('rx_backpressure',0):,} 次 / 日志未保存 {s.metrics.get('log_dropped',0):,} 条")
    def password(self,p):
        if p.id in self.memory_passwords:return self.memory_passwords[p.id]
        try:return self.store.password(p)
        except Exception:return ''
    def save_dialog(self,d,existing=None):
        if d.exec()!=QDialog.Accepted:return
        p=d.profile
        if existing is None:self.profiles.append(p)
        else:self.profiles[existing]=p
        self.memory_passwords[p.id]=d.password.text()
        if d.remember.isChecked():
            try:self.store.save_password(p,d.password.text())
            except Exception:QMessageBox.warning(self,'密码未保存','系统凭据库不可用，密码仅保留到本次软件退出。')
        else:
            try:self.store.delete_password(p)
            except Exception:QMessageBox.warning(self,'凭据清理失败','系统凭据库中的旧密码未能删除，请检查系统凭据库。')
        self.store.save(self.profiles);self.populate()
    def add(self):self.save_dialog(ProfileDialog(Profile(),'',self))
    def edit(self):
        p=self.current()
        if not p:return
        if self.running(p):QMessageBox.information(self,'连接运行中','请先断开该连接再编辑。');return
        self.save_dialog(ProfileDialog(p,self.password(p),self),self.list.currentRow())
    def duplicate(self):
        p=self.current()
        if not p:return
        q=dataclasses.replace(p,id=Profile().id,name=p.name+' 副本')
        self.save_dialog(ProfileDialog(q,'',self))
    def delete(self):
        p=self.current()
        if not p or self.running(p):return
        if QMessageBox.question(self,'删除连接','删除 '+p.name+' 的本地配置？')!=QMessageBox.Yes:return
        try:self.store.delete_password(p)
        except Exception:
            QMessageBox.warning(self,'删除失败','无法清理系统凭据库，请稍后重试。');return
        self.memory_passwords.pop(p.id,None)
        self.profiles.remove(p);self.store.save(self.profiles);self.populate()
    def connect_selected(self):
        p=self.current()
        if not p or self.running(p):return
        password=self.password(p)
        if not password:
            password,ok=QInputDialog.getText(self,'VPN 密码',p.username,QLineEdit.Password)
            if not ok:return
        self.log_lines[p.id]=[];self.details.pop(p.id,None)
        session=Session(dataclasses.replace(p),password,self.registry,self.signals.message.emit,self.event_log)
        self.sessions[p.id]=session;session.start();self.refresh()
    def disconnect_selected(self):
        p=self.current()
        if self.running(p):self.sessions[p.id].stop()
    def message(self,id,event,data):
        p=next((p for p in self.profiles if p.id==id),None)
        if not p:return
        if event=='state':self.states[id]=(data['state'],data['text'])
        elif event=='connected':self.details[id]=data
        elif event=='sms':
            code,ok=QInputDialog.getText(self,'短信验证',p.name+'：输入本次新收到的验证码',QLineEdit.Password)
            if ok:self.sessions[id].answer('sms',code)
            else:self.sessions[id].stop()
        elif event=='certificate':
            ok=QMessageBox.question(self,'首次连接确认',f"{p.host}:{p.port}\n证书 SHA256：\n{data['fingerprint']}\n确认信任并保存此网关证书？")==QMessageBox.Yes
            self.sessions[id].answer('certificate',ok)
        elif event=='pin_saved':p.pin=data['fingerprint'];self.store.save(self.profiles)
        elif event=='error':pass
        if event!='traffic':
            text=data.get('text') or data.get('message') or {'connected':'系统网卡及内网路由安装完成','sms':'等待短信验证','pin_saved':'网关证书已保存'}.get(event,event)
            self.log_lines.setdefault(id,[]).append(time.strftime('%H:%M:%S')+'  '+text)
            del self.log_lines[id][:-500]
        self.refresh()
        if event=='error':
            dialog=QMessageBox(QMessageBox.Warning,p.name,data['message'],QMessageBox.Ok,self)
            dialog.setAttribute(Qt.WA_DeleteOnClose);dialog.open()
    def elevate(self):
        import subprocess
        args=subprocess.list2cmdline(relaunch_args(self.store.path.parent))
        result=ctypes.windll.shell32.ShellExecuteW(None,'runas',sys.executable,args,os.getcwd(),1)
        if result>32:self.close()
    def closeEvent(self,event):
        active=[s for s in self.sessions.values() if s.is_alive()]
        if active:
            for s in active:s.stop()
            event.ignore();self.setEnabled(False);QTimer.singleShot(250,self.close);return
        self.event_log.close();event.accept()

def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--data-dir');parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--self-test-report')
    options,qt_args=parser.parse_known_args()
    if options.self_test:
        from .runtime import frozen_self_test
        sys.exit(frozen_self_test(options.self_test_report))
    if options.data_dir:os.environ['MULTIVPN_DATA_DIR']=options.data_dir
    app=QApplication([sys.argv[0],*qt_args]);app.setApplicationName('MultiVPN');app.setApplicationVersion(__version__)
    from PySide6.QtGui import QIcon
    app.setWindowIcon(QIcon(str(resource_root()/'assets/icon.png')))
    if sys.platform=='darwin' and getattr(sys,'frozen',False) and os.geteuid()!=0:
        from .model import config_dir
        from .runtime import launch_macos_admin
        try:launch_macos_admin(config_dir())
        except RuntimeError as exc:QMessageBox.warning(None,'启动未完成',str(exc))
        return
    app.setStyle('Fusion');app.setStyleSheet('''
        QWidget { font-size: 14px; } QMainWindow { background: #f4f6fa; }
        QLabel#title { font-size: 28px; font-weight: 700; color: #17243a; }
        QLabel#heading { font-size: 22px; font-weight: 600; }
        QPushButton { padding: 9px 16px; border: 1px solid #cbd3df; border-radius: 6px; background: white; }
        QPushButton#primary { background: #2867da; color: white; } QPushButton:disabled { color: #a5aebb; }
        QLineEdit,QSpinBox,QListWidget,QPlainTextEdit { background: white; border: 1px solid #d5dce7; border-radius: 5px; padding: 7px; }
        QListWidget::item { padding: 12px 4px; } QListWidget::item:selected { background: #dbe9ff; color: #153b77; }
    ''')
    window=Window();window.show();sys.exit(app.exec())
