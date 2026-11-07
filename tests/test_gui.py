import os
import uuid
import pytest
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')


class SimulatedSession:
    """Drive UI events without opening sockets, creating adapters or reading credentials."""
    def __init__(self,profile,password,registry,emit,event_log):
        self.profile=profile;self.emit_callback=emit;self.run_id=uuid.uuid4().hex
        self.alive=False;self.stopped=False;self.answers=[]
        self.tx=1024;self.rx=2048;self.metrics={}

    def start(self):self.alive=True
    def is_alive(self):return self.alive
    def stop(self):self.stopped=True
    def answer(self,*args):self.answers.append(args)
    def emit(self,event,**data):
        self.emit_callback(self.profile.id,event,dict(data,run_id=self.run_id))
    def finish(self):
        self.alive=False;self.emit('state',state='disconnected',text='已断开')


@pytest.fixture
def gui(tmp_path,monkeypatch):
    import socket
    import multi_vpn.model as model
    import multi_vpn.app as ui
    from PySide6.QtWidgets import QApplication,QMessageBox
    from PySide6.QtCore import QObject,Signal
    from unittest.mock import Mock
    real_tray=ui.QSystemTrayIcon
    class SimulatedTray(QObject):
        activated=Signal(object)
        messageClicked=Signal()
        ActivationReason=real_tray.ActivationReason
        MessageIcon=real_tray.MessageIcon
        available=True
        messages_supported=True
        def __init__(self,parent):
            super().__init__(parent);self.visible=False;self.notifications=[]
        @staticmethod
        def isSystemTrayAvailable():return SimulatedTray.available
        @staticmethod
        def supportsMessages():return SimulatedTray.messages_supported
        def show(self):self.visible=True
        def hide(self):self.visible=False
        def isVisible(self):return self.visible
        def setIcon(self,icon):self.current_icon=icon
        def icon(self):return self.current_icon
        def setToolTip(self,text):self.tooltip=text
        def toolTip(self):return self.tooltip
        def setContextMenu(self,menu):self.menu=menu
        def showMessage(self,*args):self.notifications.append(args)
    monkeypatch.setattr(ui,'QSystemTrayIcon',SimulatedTray)
    monkeypatch.setattr(model,'config_dir',lambda:tmp_path)
    def no_network(*args,**kwargs):raise AssertionError('GUI tests must not access the network')
    monkeypatch.setattr(socket,'create_connection',no_network)
    monkeypatch.setattr(ui,'Session',SimulatedSession)
    monkeypatch.setattr(QMessageBox,'open',lambda self:None)
    model.Store().save([model.Profile(name='办公网络',host='vpn.example.test',username='demo'),
                        model.Profile(name='测试网络',host='test.example.test',username='demo')])
    app=QApplication.instance() or QApplication([])
    monkeypatch.setattr(app,'quit',Mock())
    app.setStyle('Fusion');app.setStyleSheet(ui.STYLE)
    window=ui.Window();window.show();app.processEvents()
    monkeypatch.setattr(window,'confirm_connection_action',lambda exiting:True)
    for profile in window.profiles:window.memory_passwords[profile.id]='synthetic'
    yield app,window
    for session in window.sessions.values():session.alive=False
    window.request_exit()
    if not window._shutdown_complete:window.close()
    app.processEvents()


def establish(window):
    window.connect_button.click()
    session=window.sessions[window.current().id]
    session.emit('connected',vip='192.0.2.2',interface='MultiVPN-demo',routes=['192.0.2.0/24'])
    session.emit('state',state='connected',text='系统内网路由已就绪')
    return session


def test_connection_feedback_and_disabled_success_color(gui):
    app,window=gui
    window.connect_button.click()
    session=window.sessions[window.current().id]
    assert window.connect_button.text()=='连接中…'
    assert not window.connect_button.isEnabled()
    assert window.disconnect_button.text()=='取消连接'
    assert window.progress.isVisible()
    session.emit('state',state='connecting',text='安装系统网卡与路由')
    assert window.status_detail.text()=='安装系统网卡与路由'
    session.emit('connected',vip='192.0.2.2',interface='MultiVPN-demo',routes=['192.0.2.0/24'])
    # Address details alone must not advertise success before the ready state.
    assert window.connect_button.text()=='连接中…'
    session.emit('state',state='connected',text='系统内网路由已就绪')
    app.processEvents()
    assert window.connect_button.text()=='已连接'
    assert not window.connect_button.isEnabled() and window.disconnect_button.isEnabled()
    assert not window.progress.isVisible() and window.duration.isVisible()
    assert window.list.item(0).text()=='办公网络  ·  已连接'
    assert not window.list.item(0).icon().isNull()
    assert '192.0.2.2' in window.info.text()
    # Verify actual Qt rendering: disabled styling must keep the success green.
    image=window.connect_button.grab().toImage()
    assert image.pixelColor(12,image.height()//2).name()=='#15803d'


def test_disconnect_feedback_blocks_late_success_and_clears_details(gui):
    app,window=gui
    session=establish(window)
    window.disconnect_button.click()
    assert session.stopped
    assert window.connect_button.text()=='断开中…'
    assert not window.disconnect_button.isEnabled() and not window.connect_button.isEnabled()
    session.emit('state',state='connected',text='延迟到达的成功状态')
    assert window.connect_button.text()=='断开中…'
    session.finish()
    assert window.connect_button.text()=='连接' and window.connect_button.isEnabled()
    assert '192.0.2.2' not in window.info.text()
    assert not window.duration.isVisible()
    assert window.traffic.text()=='发送 0 B / 接收 0 B'


def test_cancel_during_setup_does_not_accept_late_adapter_details(gui):
    app,window=gui
    window.connect_button.click();session=window.sessions[window.current().id]
    window.disconnect_button.click()
    session.emit('connected',vip='192.0.2.2',interface='MultiVPN-demo',routes=['192.0.2.0/24'])
    session.emit('state',state='connected',text='已就绪')
    assert window.connect_button.text()=='断开中…'
    assert '虚拟 IP' not in window.info.text()
    session.finish()
    assert window.connect_button.isEnabled()


@pytest.mark.parametrize('already_connected,title',[(False,'连接失败'),(True,'连接中断')])
def test_error_remains_after_cleanup_and_retry_ignores_old_events(gui,already_connected,title):
    app,window=gui
    if already_connected:session=establish(window)
    else:
        window.connect_button.click();session=window.sessions[window.current().id]
    session.emit('error',message='网关关闭连接')
    assert title in window.status.text()
    assert not window.connect_button.isEnabled()  # Cleanup thread still running.
    session.emit('error',message='网卡清理失败')
    session.finish()
    assert title in window.status.text()
    assert window.status_detail.text()=='网关关闭连接'
    assert window.connect_button.text()=='重新连接' and window.connect_button.isEnabled()
    assert '虚拟 IP' not in window.info.text()
    window.connect_button.click()
    session.emit('state',state='disconnected',text='上一次连接的延迟事件')
    session.emit('error',message='上一次连接的错误')
    assert window.connect_button.text()=='连接中…'
    assert '上一次' not in window.logs.toPlainText()


def test_multi_connection_summary_and_warning_recovery_keep_elapsed_time(gui,monkeypatch):
    import multi_vpn.app as ui
    clock=[100.0];monkeypatch.setattr(ui.time,'monotonic',lambda:clock[0])
    app,window=gui
    first=establish(window)
    window.list.setCurrentRow(1)
    assert window.connect_button.text()=='连接'
    assert window.summary.text()=='已连接 1 条'
    assert '已连接 1 条' in window.windowTitle()
    second=establish(window)
    healthy_icon=window.windowIcon().cacheKey()
    first.emit('state',state='degraded',text='超过 30 秒未收到内网数据，请检查目标服务')
    assert window.summary.text()=='已连接 2 条 · 1 条链路异常'
    assert window.windowIcon().cacheKey()!=healthy_icon
    assert window.connect_button.text()=='已连接'  # Selected connection is healthy.
    window.list.setCurrentRow(0)
    assert window.connect_button.text()=='链路异常' and window.disconnect_button.isEnabled()
    clock[0]=165.0
    first.emit('state',state='connected',text='已恢复接收内网数据')
    assert window.duration.text()=='连接时长 00:01:05'
    assert window.summary.text()=='已连接 2 条'
    assert window.windowIcon().cacheKey()==healthy_icon
    first.finish()
    assert window.summary.text()=='已连接 1 条'
    second.finish()
    assert window.summary.text()=='未连接'


@pytest.mark.parametrize('kind',['sms','certificate'])
def test_verification_feedback_and_cancel(gui,monkeypatch,kind):
    from PySide6.QtWidgets import QInputDialog,QMessageBox
    app,window=gui
    window.connect_button.click();session=window.sessions[window.current().id]
    def cancel(*args,**kwargs):
        assert window.connect_button.text()=='等待验证…'
        assert not window.connect_button.isEnabled()
        assert window.status_panel.property('state')==kind
        return ('',False) if kind=='sms' else QMessageBox.No
    if kind=='sms':monkeypatch.setattr(QInputDialog,'getText',cancel)
    else:monkeypatch.setattr(QMessageBox,'question',cancel)
    session.emit(kind,fingerprint='synthetic-fingerprint')
    assert session.stopped and window.connect_button.text()=='断开中…'
    session.finish()
    assert window.connect_button.isEnabled() and window.status_detail.text()=='连接已断开'


def test_verification_dialog_cancel_after_timeout_preserves_failure(gui,monkeypatch):
    from PySide6.QtWidgets import QInputDialog
    app,window=gui
    window.connect_button.click();session=window.sessions[window.current().id]
    def timeout_then_cancel(*args,**kwargs):
        session.emit('error',message='等待用户输入超时，请重新连接');session.finish()
        return '',False
    monkeypatch.setattr(QInputDialog,'getText',timeout_then_cancel)
    session.emit('sms')
    assert '连接失败' in window.status.text()
    assert window.status_detail.text()=='等待用户输入超时，请重新连接'
    assert window.connect_button.isEnabled()


def test_removing_last_profile_resets_the_detail_panel(gui):
    app,window=gui
    session=establish(window);session.finish()
    window.profiles.clear();window.populate()
    assert window.heading.text()=='选择或新增连接'
    assert window.info.text()=='' and window.logs.toPlainText()==''
    assert not window.connect_button.isEnabled() and not window.disconnect_button.isEnabled()


def test_close_hides_to_tray_without_stopping_connections_and_hints_once(gui):
    app,window=gui
    session=establish(window)
    window.close();app.processEvents()
    assert not window.isVisible() and window.tray.isVisible()
    assert session.is_alive() and not session.stopped
    assert not window.event_log.closed and window.timer.isActive()
    app.quit.assert_not_called()
    assert len(window.tray.notifications)==1
    session.emit('state',state='degraded',text='暂未收到回包')
    assert '1 条链路异常' in window.tray.toolTip()
    window.tray.activated.emit(window.tray.ActivationReason.Trigger)
    assert window.isVisible() and window.connect_button.text()=='链路异常'
    window.close()
    assert len(window.tray.notifications)==1


def test_minimize_keeps_the_window_in_the_taskbar_and_tray_restores_it(gui):
    app,window=gui
    session=establish(window)
    window.showMinimized();app.processEvents()
    assert window.isMinimized() and window.isVisible()
    assert session.is_alive() and not session.stopped
    assert not window.tray.notifications
    window.tray.activated.emit(window.tray.ActivationReason.Context)
    assert window.isMinimized()  # Right-click opens the menu, not the window.
    window.show_action.trigger();app.processEvents()
    assert window.isVisible() and not window.isMinimized()


@pytest.mark.parametrize('activation',['Trigger','DoubleClick','message'])
def test_tray_click_and_notification_restore_hidden_window(gui,activation):
    app,window=gui
    window.close()
    if activation=='message':window.tray.messageClicked.emit()
    else:window.tray.activated.emit(getattr(window.tray.ActivationReason,activation))
    assert window.isVisible()


def test_tray_unavailable_keeps_window_and_connections_accessible(gui):
    app,window=gui
    session=establish(window)
    type(window.tray).available=False
    window.close();app.processEvents()
    assert window.isVisible() and '系统托盘不可用' in window.lifecycle_status.text()
    assert session.is_alive() and not session.stopped
    assert not window.event_log.closed
    app.quit.assert_not_called()


def test_losing_tray_while_hidden_restores_window(gui):
    app,window=gui
    window.close()
    type(window.tray).available=False
    window.refresh()
    assert window.isVisible() and '系统托盘不可用' in window.lifecycle_status.text()


def test_tray_does_not_require_notification_support(gui):
    app,window=gui
    type(window.tray).messages_supported=False
    window.close()
    assert not window.isVisible() and not window.tray.notifications


def test_disconnect_all_from_tray_keeps_program_running(gui):
    app,window=gui
    first=establish(window);window.list.setCurrentRow(1);second=establish(window)
    window.close()
    window.disconnect_all_action.trigger()
    assert first.stopped and second.stopped
    assert first.is_alive() and second.is_alive()
    assert not window.disconnect_all_action.isEnabled()
    assert not window.isVisible() and not window.event_log.closed
    first.finish();second.finish()
    assert window.tray.toolTip()=='Multi VPN\n未连接'
    app.quit.assert_not_called()


def test_exit_waits_for_all_sessions_before_closing_log_and_tray(gui):
    app,window=gui
    first=establish(window);window.list.setCurrentRow(1);second=establish(window)
    window.close();window.exit_action.trigger()
    assert window.isVisible() and not window.isEnabled()
    assert '正在断开所有 VPN' in window.lifecycle_status.text()
    assert first.stopped and second.stopped
    assert window.exit_timer.isActive() and not window.event_log.closed
    app.quit.assert_not_called()
    first.finish();window.close()
    assert not window.event_log.closed
    second.finish();window.close()
    assert not window.tray.isVisible() and not window.isVisible()
    assert window.event_log.closed and not window.timer.isActive() and not window.exit_timer.isActive()
    app.quit.assert_called_once()
    window.request_exit();window.close()
    app.quit.assert_called_once()


@pytest.mark.parametrize('entry',['button','shortcut'])
def test_main_window_exit_entries(gui,entry):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    app,window=gui
    if entry=='button':window.exit_button.click()
    else:
        window.activateWindow();app.processEvents()
        QTest.keyClick(window,Qt.Key_Q,Qt.ControlModifier)
        app.processEvents()
    assert window.event_log.closed and not window.tray.isVisible()
    app.quit.assert_called_once()


@pytest.mark.parametrize('kind',['sms','certificate'])
def test_background_verification_restores_main_window(gui,monkeypatch,kind):
    from PySide6.QtWidgets import QInputDialog,QMessageBox
    app,window=gui
    window.connect_button.click();session=window.sessions[window.current().id]
    window.close()
    def confirm(*args,**kwargs):
        assert window.isVisible()
        return ('123456',True) if kind=='sms' else QMessageBox.Yes
    if kind=='sms':monkeypatch.setattr(QInputDialog,'getText',confirm)
    else:monkeypatch.setattr(QMessageBox,'question',confirm)
    session.emit(kind,fingerprint='synthetic-fingerprint')
    assert session.answers==[(kind,'123456' if kind=='sms' else True)]
    assert not session.stopped


def test_elevated_restart_exits_old_process_instead_of_hiding(gui,monkeypatch):
    import ctypes,sys
    if sys.platform!='win32':pytest.skip('Windows elevation only')
    app,window=gui
    monkeypatch.setattr(ctypes.windll.shell32,'ShellExecuteW',lambda *args:33)
    window.elevate()
    assert window.event_log.closed and not window.tray.isVisible()
    app.quit.assert_called_once()


def test_event_loop_survives_close_then_exits_after_cleanup(tmp_path):
    import subprocess,sys,textwrap
    script=textwrap.dedent('''
        import os
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from multi_vpn.app import Window
        from multi_vpn.model import Store,Profile
        app=QApplication([]);app.setQuitOnLastWindowClosed(False)
        Store().save([Profile(name='Offline test')])
        window=Window();window.show()
        window.confirm_connection_action=lambda exiting:True
        class Session:
            alive=True
            stopped=False
            tx=0;rx=0;metrics={}
            def is_alive(self):return self.alive
            def stop(self):self.stopped=True
        session=Session();window.sessions[window.profiles[0].id]=session
        window.tray_available=lambda:True
        window._tray_hint_shown=True
        checks=[]
        def hide():window.close()
        def verify_background():
            checks.append(not window.isVisible() and not session.stopped and not window.event_log.closed)
            window.request_exit()
            checks.append(session.stopped and not window.event_log.closed)
        def finish():
            checks.append(not window.event_log.closed)
            session.alive=False
        QTimer.singleShot(0,hide)
        QTimer.singleShot(40,verify_background)
        QTimer.singleShot(140,finish)
        QTimer.singleShot(5000,lambda:app.exit(9))
        result=app.exec()
        assert result==0 and checks==[True,True,True]
        assert window.event_log.closed and window._shutdown_complete
        print('background-and-cleanup-ok')
    ''')
    env=dict(os.environ,MULTIVPN_DATA_DIR=str(tmp_path),QT_QPA_PLATFORM='offscreen')
    result=subprocess.run([sys.executable,'-c',script],env=env,capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stdout+result.stderr
    assert 'background-and-cleanup-ok' in result.stdout


def test_gui_starts_without_network(tmp_path,monkeypatch):
    import multi_vpn.model as model
    monkeypatch.setattr(model,'config_dir',lambda:tmp_path)
    from PySide6.QtWidgets import QApplication
    from multi_vpn.app import Window
    app=QApplication.instance() or QApplication([])
    window=Window();window.show();app.processEvents()
    assert window.windowTitle().startswith('Multi VPN · ')
    assert not window.connect_button.isEnabled()
    window.request_exit()

def test_windows_admin_restart_preserves_configuration_directory(tmp_path,monkeypatch):
    import sys,ctypes
    import pytest
    if sys.platform!='win32':pytest.skip('Windows elevation only')
    import multi_vpn.model as model
    location=tmp_path/'user profiles';location.mkdir()
    monkeypatch.setattr(model,'config_dir',lambda:location)
    calls=[]
    monkeypatch.setattr(ctypes.windll.shell32,'ShellExecuteW',lambda *args:calls.append(args) or 0)
    from PySide6.QtWidgets import QApplication
    from multi_vpn.app import Window
    app=QApplication.instance() or QApplication([])
    window=Window();window.elevate()
    assert calls[0][1]=='runas'
    assert '--data-dir "'+str(location.resolve())+'"' in calls[0][3]
    window.request_exit()
