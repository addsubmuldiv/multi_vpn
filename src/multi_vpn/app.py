import ctypes,dataclasses,os,sys,time
from PySide6.QtCore import Qt,Signal,QObject,QTimer,QSize,QEvent
from PySide6.QtGui import QIcon,QAction,QKeySequence
from PySide6.QtWidgets import (QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QListWidget,
    QPushButton,QLabel,QLineEdit,QSpinBox,QDialog,QDialogButtonBox,QFormLayout,QMessageBox,
    QPlainTextEdit,QInputDialog,QCheckBox,QSplitter,QProgressBar,QSizePolicy,QSystemTrayIcon,QMenu)
from .model import Profile,Store,RouteRegistry
from .session import Session
from .runtime import resource_root,relaunch_args
from . import __version__
from .diagnostics import EventLog
from .presentation import STATES,STYLE,state_icon,badged_icon,set_state

class Signals(QObject):
    message=Signal(str,str,dict)

class WrappingLabel(QLabel):
    """Keep all lines visible when the details column is resized."""
    def setText(self,text):
        super().setText(text)
        if self.isVisible():self.fit_height()
    def resizeEvent(self,event):
        super().resizeEvent(event);self.fit_height()
    def fit_height(self):
        if self.wordWrap():self.setMinimumHeight(self.heightForWidth(self.width()))

class PasswordInput(QWidget):
    def __init__(self,password='',parent=None):
        super().__init__(parent);layout=QHBoxLayout(self);layout.setContentsMargins(0,0,0,0)
        self.edit=QLineEdit(password);self.edit.setEchoMode(QLineEdit.Password)
        self.show_password=QCheckBox('显示密码')
        self.show_password.toggled.connect(lambda show:self.edit.setEchoMode(QLineEdit.Normal if show else QLineEdit.Password))
        layout.addWidget(self.edit,1);layout.addWidget(self.show_password)
    def text(self):return self.edit.text()

def password_prompt(parent,title,label):
    dialog=QDialog(parent);dialog.setWindowTitle(title);layout=QFormLayout(dialog)
    password=PasswordInput();layout.addRow(label,password)
    buttons=QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel)
    buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);layout.addRow(buttons)
    if dialog.exec()!=QDialog.Accepted:return '',False
    return password.text(),True

class ProfileDialog(QDialog):
    def __init__(self,profile,password,parent):
        super().__init__(parent);self.setWindowTitle('连接配置');self.resize(450,330)
        self.profile=dataclasses.replace(profile);layout=QFormLayout(self)
        self.name=QLineEdit(profile.name);self.host=QLineEdit(profile.host)
        self.port=QSpinBox();self.port.setRange(1,65535);self.port.setValue(profile.port)
        self.username=QLineEdit(profile.username);self.password=PasswordInput(password)
        self.remember=QCheckBox('保存密码');self.remember.setChecked(bool(password))
        for title,w in [('名称',self.name),('VPN 网关',self.host),('端口',self.port),('账号',self.username),('密码',self.password)]:layout.addRow(title,w)
        layout.addRow(self.remember)
        self.legacy_udp=QCheckBox('旧版网关优先使用 UDP')
        self.legacy_udp.setChecked(profile.legacy_udp)
        layout.addRow(self.legacy_udp)
        self.mtu=QSpinBox();self.mtu.setRange(576,1400);self.mtu.setValue(profile.mtu)
        layout.addRow('隧道 MTU',self.mtu)
        self.auto_mtu=QCheckBox('连接时探测 UDP 路径 MTU（实验）')
        self.auto_mtu.setChecked(profile.auto_mtu)
        layout.addRow(self.auto_mtu)
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
        self.profile.legacy_udp=self.legacy_udp.isChecked()
        self.profile.mtu=self.mtu.value()
        self.profile.auto_mtu=self.auto_mtu.isChecked()
        super().accept()

class Window(QMainWindow):
    SHUTDOWN_TIMEOUT=15
    def __init__(self):
        super().__init__();self.setWindowTitle('Multi VPN · '+__version__);self.resize(1020,690)
        self.store=Store();self.profiles=self.store.load();self.sessions={};self.states={};self.details={};self.memory_passwords={}
        self.errors={};self.connected_since={}
        self.state_icons={state:state_icon(state) for state in STATES}
        base_icon=QIcon(str(resource_root()/'assets/icon.png'))
        self.app_icons={state:badged_icon(base_icon,state,self.state_icons) for state in STATES}
        self._icon_state=None
        self.event_log=EventLog(self.store.path.parent/'logs')
        self.registry=RouteRegistry();self.signals=Signals();self.signals.message.connect(self.message)
        self._closing=False;root=QWidget();self.setCentralWidget(root);outer=QVBoxLayout(root)
        header=QHBoxLayout();outer.addLayout(header)
        title=QLabel('Multi VPN');title.setObjectName('title');header.addWidget(title)
        header.addStretch();self.summary=QLabel();self.summary.setObjectName('summary');header.addWidget(self.summary)
        outer.addWidget(QLabel('多个独立连接 · 系统内网访问'))
        self.permission=QLabel();outer.addWidget(self.permission)
        if sys.platform=='win32' and not ctypes.windll.shell32.IsUserAnAdmin():
            self.permission.setText('创建系统网卡需要管理员权限。')
            elevate=QPushButton('以管理员身份重新启动');elevate.clicked.connect(self.elevate);outer.addWidget(elevate)
        elif sys.platform=='darwin' and os.geteuid()!=0:self.permission.setText('连接时将请求管理员授权以创建系统网卡。')
        split=QSplitter();outer.addWidget(split,1)
        left=QWidget();ll=QVBoxLayout(left);self.list=QListWidget();self.list.setIconSize(QSize(20,20));self.list.currentRowChanged.connect(self.refresh);ll.addWidget(self.list)
        actions=QHBoxLayout();ll.addLayout(actions)
        for label,fn in [('新增',self.add),('编辑',self.edit),('删除',self.delete)]:
            b=QPushButton(label);b.clicked.connect(fn);actions.addWidget(b)
        duplicate=QPushButton('复制配置');duplicate.clicked.connect(self.duplicate);ll.addWidget(duplicate)
        right=QWidget();rl=QVBoxLayout(right);self.heading=QLabel('选择或新增连接');self.heading.setObjectName('heading');rl.addWidget(self.heading)
        self.status_panel=QWidget();self.status_panel.setObjectName('statusPanel');status_layout=QVBoxLayout(self.status_panel)
        status_heading=QHBoxLayout();status_layout.addLayout(status_heading)
        self.status_icon=QLabel();self.status_icon.setFixedSize(28,28);status_heading.addWidget(self.status_icon)
        self.status=QLabel('未连接');self.status.setObjectName('connectionStatus');status_heading.addWidget(self.status,1)
        self.status_detail=WrappingLabel();self.status_detail.setObjectName('statusDetail');self.status_detail.setWordWrap(True);status_layout.addWidget(self.status_detail)
        self.duration=QLabel();self.duration.setObjectName('duration');status_layout.addWidget(self.duration)
        self.progress=QProgressBar();self.progress.setRange(0,0);self.progress.setTextVisible(False);self.progress.setFixedHeight(4);status_layout.addWidget(self.progress)
        rl.addWidget(self.status_panel)
        self.info=WrappingLabel('');self.info.setWordWrap(True);self.info.setTextInteractionFlags(Qt.TextSelectableByMouse);rl.addWidget(self.info)
        self.info.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Minimum)
        self.traffic=QLabel('发送 0 B / 接收 0 B');self.traffic.setWordWrap(True);rl.addWidget(self.traffic)
        buttons=QHBoxLayout();rl.addLayout(buttons)
        self.connect_button=QPushButton('连接');self.connect_button.setObjectName('primary');self.connect_button.clicked.connect(self.connect_selected);buttons.addWidget(self.connect_button)
        self.connect_button.setIconSize(QSize(20,20))
        self.disconnect_button=QPushButton('断开');self.disconnect_button.clicked.connect(self.disconnect_selected);buttons.addWidget(self.disconnect_button)
        rl.addWidget(QLabel('连接日志'));self.logs=QPlainTextEdit();self.logs.setReadOnly(True);self.logs.setMaximumBlockCount(500);rl.addWidget(self.logs,1)
        log_location=QLabel('诊断日志：'+str(self.event_log.path) if self.event_log.handler else '诊断日志无法写入，请检查配置目录权限')
        log_location.setTextInteractionFlags(Qt.TextSelectableByMouse);log_location.setWordWrap(True);rl.addWidget(log_location)
        split.addWidget(left);split.addWidget(right);split.setSizes([310,710])
        footer=QHBoxLayout();outer.addLayout(footer)
        self.lifecycle_status=QLabel();self.lifecycle_status.setWordWrap(True);footer.addWidget(self.lifecycle_status,1)
        self.exit_button=QPushButton('退出程序');self.exit_button.setObjectName('exitButton');self.exit_button.setFlat(True)
        self.exit_button.setToolTip('断开所有 VPN 并退出程序（Ctrl+Q）');self.exit_button.clicked.connect(self.request_exit);footer.addWidget(self.exit_button)
        self._tray_hint_shown=False;self._shutdown_complete=False;self._hidden_to_tray=False;self._shutdown_started=None
        self._confirmation_dialog=None
        self.exit_timer=QTimer(self);self.exit_timer.setInterval(100);self.exit_timer.timeout.connect(self.close)
        self.setup_tray()
        self.log_lines={};self.populate()
        self.timer=QTimer(self);self.timer.timeout.connect(self.refresh);self.timer.start(1000)
        QApplication.instance().installEventFilter(self)
    def eventFilter(self,watched,event):
        if watched is QApplication.instance() and event.type()==QEvent.Quit and not self._shutdown_complete:
            self.request_exit()
            return True
        return super().eventFilter(watched,event)
    def setup_tray(self):
        self.tray=QSystemTrayIcon(self)
        self.tray_menu=QMenu(self)
        self.show_action=self.tray_menu.addAction('显示主窗口',self.show_window)
        self.disconnect_all_action=self.tray_menu.addAction('断开全部连接',self.disconnect_all)
        self.tray_menu.addSeparator()
        self.exit_action=QAction('退出程序',self)
        self.exit_action.setShortcut(QKeySequence('Ctrl+Q'))
        self.exit_action.setShortcutContext(Qt.ApplicationShortcut)
        self.exit_action.triggered.connect(self.request_exit)
        self.addAction(self.exit_action);self.tray_menu.addAction(self.exit_action)
        self.tray.setContextMenu(self.tray_menu)
        self.tray.activated.connect(self.tray_activated)
        self.tray.messageClicked.connect(self.show_window)
        self.tray.setIcon(self.app_icons['disconnected'])
        if QSystemTrayIcon.isSystemTrayAvailable():self.tray.show()
    def tray_available(self):
        return QSystemTrayIcon.isSystemTrayAvailable() and self.tray.isVisible()
    def tray_activated(self,reason):
        if reason in {QSystemTrayIcon.ActivationReason.Trigger,QSystemTrayIcon.ActivationReason.DoubleClick}:
            self.show_window()
    def show_window(self):
        if self._shutdown_complete:return
        self._hidden_to_tray=False
        if self.isMinimized():self.showNormal()
        else:self.show()
        self.raise_();self.activateWindow()
    def keep_window_visible(self):
        self.show_window()
        self.lifecycle_status.setText('系统托盘不可用，窗口已保留。请使用右下角“退出程序”或 Ctrl+Q 退出。')
    def disconnect_all(self):
        if self._closing or self._shutdown_complete:return
        if not self.confirm_connection_action(exiting=False):return
        self.stop_all_sessions()
    def connection_action_dialog(self,exiting,count):
        title='退出程序确认' if exiting else '断开全部连接确认'
        dialog=QMessageBox(QMessageBox.Warning,title,f'当前有 {count} 条 VPN 连接正在运行或建立。',parent=self)
        dialog.setTextFormat(Qt.PlainText)
        dialog.setInformativeText(('退出程序将断开全部连接。' if exiting else '此操作将断开全部连接，程序会继续运行。')+
                                  '\n可能中断 SSH、下载或远程开发等网络任务。')
        cancel=dialog.addButton('取消',QMessageBox.RejectRole)
        cancel.setObjectName('cancelConnectionAction')
        confirm=dialog.addButton('断开并退出' if exiting else '断开全部连接',QMessageBox.DestructiveRole)
        confirm.setObjectName('confirmConnectionAction')
        dialog.setDefaultButton(cancel);dialog.setEscapeButton(cancel)
        return dialog,confirm
    def confirm_connection_action(self,exiting):
        if self._confirmation_dialog is not None:
            self._confirmation_dialog.raise_();self._confirmation_dialog.activateWindow()
            return False
        count=sum(session.is_alive() for session in self.sessions.values())
        if not count:return True
        dialog,confirm=self.connection_action_dialog(exiting,count)
        self._confirmation_dialog=dialog
        try:
            dialog.exec()
            return dialog.clickedButton() is confirm
        finally:
            self._confirmation_dialog=None;dialog.deleteLater()
    def stop_all_sessions(self):
        for profile in self.profiles:
            if self.running(profile) and self.state(profile.id)[0]!='disconnecting':self.stop_session(profile.id)
    def request_exit(self):
        if self._shutdown_complete or self._closing:return
        if not self.confirm_connection_action(exiting=True):return
        self.begin_exit()
    def begin_exit(self):
        self._closing=True
        self._shutdown_started=time.monotonic()
        self.show_window()
        for dialog in self.findChildren(QDialog):dialog.reject()
        self.lifecycle_status.setText('正在断开所有 VPN 并清理系统网卡与路由，请稍候…')
        self.exit_action.setEnabled(False);self.setEnabled(False)
        self.stop_all_sessions()
        self.close()
    def current(self):
        i=self.list.currentRow();return self.profiles[i] if 0<=i<len(self.profiles) else None
    def running(self,p):return p and p.id in self.sessions and self.sessions[p.id].is_alive()
    def populate(self):
        i=self.list.currentRow();self.list.blockSignals(True);self.list.clear()
        for p in self.profiles:self.list.addItem(p.name)
        self.list.setCurrentRow(max(0,min(i,len(self.profiles)-1)));self.list.blockSignals(False);self.refresh()
    def state(self,id):
        return self.states.get(id,('disconnected','尚未建立 VPN 连接'))
    def refresh_summary(self):
        states=[self.state(profile.id)[0] for profile in self.profiles]
        connected=sum(state in {'connected','degraded'} for state in states)
        warnings=states.count('degraded')
        failures=sum(s in {'failed','interrupted'} for s in states)
        if warnings or failures:
            state='degraded' if connected else 'failed'
            text=f'已连接 {connected} 条' if connected else '未连接'
            if warnings:text+=f' · {warnings} 条链路异常'
            if failures:text+=f' · {failures} 条连接失败'
        elif connected:state='connected';text=f'已连接 {connected} 条'
        elif any(s in {'connecting','certificate','sms'} for s in states):state='connecting';text='正在建立连接'
        elif 'disconnecting' in states:state='disconnecting';text='正在断开连接'
        else:state='disconnected';text='未连接'
        self.summary.setText(text);set_state(self.summary,state)
        self.setWindowTitle('Multi VPN · '+__version__+' · '+text)
        if self._icon_state!=state:
            self.setWindowIcon(self.app_icons[state]);self.tray.setIcon(self.app_icons[state]);self._icon_state=state
        self.tray.setToolTip('Multi VPN\n'+text)
        self.disconnect_all_action.setEnabled(not self._closing and any(self.running(p) and self.state(p.id)[0]!='disconnecting' for p in self.profiles))
        if not self._closing:
            if QSystemTrayIcon.isSystemTrayAvailable():
                if not self.tray.isVisible():self.tray.show()
            elif self._hidden_to_tray:self.keep_window_visible()
    def refresh(self):
        p=self.current();active=self.running(p)
        state,detail=self.state(p.id) if p else ('disconnected','新增或选择一条连接以开始使用')
        appearance=STATES[state]
        self.connect_button.setText(appearance.button);set_state(self.connect_button,state)
        self.connect_button.setIcon(self.state_icons[state] if state!='disconnected' else QIcon())
        self.connect_button.setEnabled(bool(p) and not active and state in {'disconnected','failed','interrupted'})
        self.disconnect_button.setText('取消连接' if state in {'connecting','certificate','sms'} else '断开')
        self.disconnect_button.setEnabled(bool(active) and state in {'connecting','certificate','sms','connected','degraded'})
        for i,profile in enumerate(self.profiles):
            row_state,row_detail=self.state(profile.id);item=self.list.item(i)
            item.setText(profile.name+'  ·  '+STATES[row_state].title)
            item.setIcon(self.state_icons[row_state]);item.setToolTip(row_detail)
        self.refresh_summary()
        self.status.setText(appearance.title);self.status_icon.setPixmap(self.state_icons[state].pixmap(28,28))
        self.status_detail.setText(detail)
        set_state(self.status_panel,state);set_state(self.status,state)
        self.progress.setVisible(state in {'connecting','disconnecting'})
        self.duration.setVisible(bool(p) and state in {'connected','degraded'})
        if p and p.id in self.connected_since:
            elapsed=max(0,int(time.monotonic()-self.connected_since[p.id]));hours,remainder=divmod(elapsed,3600);minutes,seconds=divmod(remainder,60)
            self.duration.setText(f'连接时长 {hours:02}:{minutes:02}:{seconds:02}')
        else:self.duration.clear()
        if not p:
            self.heading.setText('选择或新增连接');self.info.clear();self.logs.clear();self.traffic.setText('发送 0 B / 接收 0 B');return
        self.heading.setText(p.name)
        d=self.details.get(p.id,{})
        text=f'网关：{p.host}:{p.port}\n账号：{p.username}'
        if d:text+=f"\n虚拟 IP：{d['vip']}\n系统网卡：{d['interface']}\n内网路由："+', '.join(d['routes'])
        if d.get('transport'):text+='\n数据通道：'+('UDP' if d['transport']=='udp' else 'TLS / TCP')
        if d.get('mtu'):text+=f"\n隧道 MTU：{d['mtu']}"
        self.info.setText(text)
        logs='\n'.join(self.log_lines.get(p.id,[]))
        if self.logs.toPlainText()!=logs:
            self.logs.setPlainText(logs)
            cursor=self.logs.textCursor();cursor.movePosition(cursor.MoveOperation.End);self.logs.setTextCursor(cursor)
        s=self.sessions.get(p.id) if state in {'connected','degraded','disconnecting'} else None
        self.traffic.setText(f'发送 {s.tx:,} B / 接收 {s.rx:,} B' if s else '发送 0 B / 接收 0 B')
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
        self.states.pop(p.id,None);self.details.pop(p.id,None);self.errors.pop(p.id,None);self.connected_since.pop(p.id,None)
        self.profiles.remove(p);self.store.save(self.profiles);self.populate()
    def connect_selected(self):
        if self._closing or self._shutdown_complete:return
        p=self.current()
        if not p or self.running(p):return
        password=self.password(p)
        if not password:
            password,ok=password_prompt(self,'VPN 密码',p.username)
            if not ok or self._closing or self._shutdown_complete:return
        self.log_lines[p.id]=[];self.details.pop(p.id,None);self.errors.pop(p.id,None);self.connected_since.pop(p.id,None)
        self.states[p.id]=('connecting','正在连接网关')
        session=Session(dataclasses.replace(p),password,self.registry,self.signals.message.emit,self.event_log)
        self.sessions[p.id]=session;session.start();self.refresh()
    def disconnect_selected(self):
        p=self.current()
        if self.running(p):self.stop_session(p.id)
    def stop_session(self,id):
        if not self.sessions[id].is_alive():self.refresh();return
        self.states[id]=('disconnecting','正在停止连接并清理系统网卡与路由，请稍候')
        self.sessions[id].stop();self.refresh()
    def message(self,id,event,data):
        if self._shutdown_complete:return
        p=next((p for p in self.profiles if p.id==id),None)
        if not p:return
        session=self.sessions.get(id)
        if session is None or data.get('run_id')!=session.run_id:return
        stopping=self.state(id)[0]=='disconnecting' or id in self.errors
        if stopping and (event in {'connected','sms','certificate'} or event=='state' and data['state']!='disconnected'):return
        if event=='state':
            state=data['state']
            if state=='disconnected':
                self.details.pop(id,None);self.connected_since.pop(id,None)
                self.states[id]=self.errors.get(id,('disconnected','连接已断开'))
            else:
                self.states[id]=(state,data['text'])
                if state=='connected':self.connected_since.setdefault(id,time.monotonic())
        elif event=='connected':self.details[id]=data
        elif event=='transport_changed' and id in self.details:self.details[id]['transport']=data['transport']
        elif event=='sms':
            self.show_window()
            self.states[id]=('sms','请输入本次收到的短信验证码');self.refresh()
            code,ok=QInputDialog.getText(self,'短信验证',p.name+'：输入本次新收到的验证码',QLineEdit.Normal)
            if self._closing or self._shutdown_complete or self.sessions.get(id) is not session:return
            if ok:self.sessions[id].answer('sms',code)
            else:self.stop_session(id)
        elif event=='certificate':
            self.show_window()
            self.states[id]=('certificate','请核对并确认网关证书指纹');self.refresh()
            ok=QMessageBox.question(self,'首次连接确认',f"{p.host}:{p.port}\n证书 SHA256：\n{data['fingerprint']}\n确认信任并保存此网关证书？")==QMessageBox.Yes
            if self._closing or self._shutdown_complete or self.sessions.get(id) is not session:return
            self.sessions[id].answer('certificate',ok)
            if not ok:self.stop_session(id)
        elif event=='pin_saved':p.pin=data['fingerprint'];self.store.save(self.profiles)
        elif event=='error':
            failure='interrupted' if id in self.connected_since else 'failed'
            self.errors.setdefault(id,(failure,data['message']));self.states[id]=self.errors[id]
            self.details.pop(id,None)
        if event!='traffic':
            text=data.get('text') or data.get('message') or {'connected':'系统网卡及内网路由安装完成','sms':'等待短信验证','pin_saved':'网关证书已保存'}.get(event,event)
            self.log_lines.setdefault(id,[]).append(time.strftime('%H:%M:%S')+'  '+text)
            del self.log_lines[id][:-500]
        self.refresh()
        if event=='error' and not self._closing:
            dialog=QMessageBox(QMessageBox.Warning,p.name,data['message'],QMessageBox.Ok,self)
            dialog.setAttribute(Qt.WA_DeleteOnClose);dialog.open()
    def elevate(self):
        if self._closing or self._shutdown_complete:return
        if not self.confirm_connection_action(exiting=True):return
        import subprocess
        args=subprocess.list2cmdline(relaunch_args(self.store.path.parent))
        result=ctypes.windll.shell32.ShellExecuteW(None,'runas',sys.executable,args,os.getcwd(),1)
        if result>32:self.begin_exit()
    def closeEvent(self,event):
        if self._shutdown_complete:event.accept();return
        if not self._closing:
            event.ignore()
            if self.tray_available():
                self._hidden_to_tray=True;self.hide()
                if not self._tray_hint_shown:
                    self._tray_hint_shown=True
                    if QSystemTrayIcon.supportsMessages():
                        self.tray.showMessage('Multi VPN','已转入后台，VPN 将继续运行。单击托盘图标可恢复窗口。',QSystemTrayIcon.MessageIcon.Information,4000)
            else:self.keep_window_visible()
            return
        active=[s for s in self.sessions.values() if s.is_alive()]
        if active:
            event.ignore()
            if time.monotonic()-self._shutdown_started>=self.SHUTDOWN_TIMEOUT:
                self.exit_timer.stop();self._closing=False;self._shutdown_started=None
                self.setEnabled(True);self.exit_action.setEnabled(True);self.show_window()
                self.lifecycle_status.setText('部分连接清理超时，程序已保留。请检查系统网络状态后重试退出；连接仍在停止中。')
                self.refresh()
                return
            if not self.exit_timer.isActive():self.exit_timer.start()
            return
        self.exit_timer.stop();self.timer.stop();self.tray.hide()
        self.event_log.close();self._shutdown_complete=True;event.accept()
        QApplication.instance().quit()

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
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(str(resource_root()/'assets/icon.png')))
    app.setStyle('Fusion');app.setStyleSheet(STYLE)
    window=Window();window.show();sys.exit(app.exec())
