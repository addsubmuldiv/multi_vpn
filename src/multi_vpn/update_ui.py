"""Schedule release checks and keep downloading off the Qt event loop."""
from datetime import datetime, timedelta
import threading

from PySide6.QtCore import QObject, QTimer, Qt, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton, QSystemTrayIcon

from . import __version__, updater


def next_daily_check(now):
    check = now.replace(hour=10, minute=0, second=0, microsecond=0)
    return check if check > now else check + timedelta(days=1)


class UpdateController(QObject):
    completed = Signal(str, object, object)
    download_progress = Signal(int)

    def __init__(self, window, footer):
        super().__init__(window)
        self.window = window
        self.button = QPushButton('检查更新', window)
        self.button.setFlat(True)
        self.button.clicked.connect(self.manual_check)
        footer.insertWidget(1, self.button)
        self.operation = None
        self.release = None
        self.installer = None
        self.notified_version = None
        self.install_pending = False
        self.installer_started = False
        self.cancel = threading.Event()
        self.completed.connect(self.finish)
        self.download_progress.connect(self.show_progress)
        self.startup = QTimer(self)
        self.startup.setSingleShot(True)
        self.startup.timeout.connect(self.automatic_check)
        self.daily = QTimer(self)
        self.daily.setSingleShot(True)
        self.daily.setTimerType(Qt.TimerType.PreciseTimer)
        self.daily.timeout.connect(self.daily_check)
        now = datetime.now()
        self.next_check = next_daily_check(now)
        if QApplication.platformName() != 'offscreen':
            self.startup.start(3000)
            self.schedule_daily(now)

    def schedule_daily(self, now):
        delay = self.next_check.timestamp() - now.timestamp()
        # Recheck wall time after sleep or a system clock adjustment.
        self.daily.start(min(60_000, max(1, round(delay * 1000))))

    def daily_check(self):
        now = datetime.now()
        if now >= self.next_check:
            self.next_check = next_daily_check(now)
            self.automatic_check()
        self.schedule_daily(now)

    def idle(self):
        return not self.operation and not self.window._closing and not self.cancel.is_set()

    def manual_check(self):
        if not self.idle():
            return
        if self.installer:
            self.ask_install()
        elif self.release:
            self.ask_download()
        else:
            self.check('manual')

    def automatic_check(self):
        if self.idle() and not self.installer:
            self.check('automatic')

    def check(self, kind):
        self.button.setText('检查更新中…')
        self.start(kind, lambda: updater.check_update(__version__))

    def start(self, kind, operation):
        self.operation = kind
        self.button.setEnabled(False)

        def worker():
            try:
                result = operation()
            except Exception as exc:
                self.completed.emit(kind, None, exc)
            else:
                self.completed.emit(kind, result, None)

        threading.Thread(target=worker, name='MultiVPN-update', daemon=True).start()

    def finish(self, kind, result, error):
        self.operation = None
        if kind == 'download' and result:
            self.installer = result
        if self.cancel.is_set():
            self.remove_download()
            return
        if kind != 'download' and error is None:
            self.release = result
        self.button.setEnabled(True)
        self.refresh_button()
        if self.window._closing:
            return
        if error:
            if kind != 'automatic':
                detail = str(error) if isinstance(error, updater.UpdateError) else '无法访问 GitHub 或写入安装包。请稍后重试。'
                QMessageBox.warning(self.window, '更新失败', detail)
        elif kind == 'download':
            self.ask_install()
        elif kind == 'manual':
            if self.release:
                self.ask_download()
            else:
                QMessageBox.information(self.window, '检查更新', f'当前版本 {__version__} 已是最新版本。')
        elif self.release and self.notified_version != self.release.version:
            self.notified_version = self.release.version
            if self.window.tray_available() and QSystemTrayIcon.supportsMessages():
                self.window.tray.showMessage('Multi VPN', f'发现新版本 {self.release.version}。打开主窗口可下载。',
                                             QSystemTrayIcon.MessageIcon.Information, 5000)

    def refresh_button(self):
        if self.installer:
            text = f'安装 {self.release.version}'
        elif self.release:
            text = f'发现新版本 {self.release.version}'
        else:
            text = '检查更新'
        self.button.setText(text)

    def ask_download(self):
        release = self.release
        choice = QMessageBox.question(self.window, '发现新版本',
                                      f'当前版本 {__version__}，最新版本 {release.version}。\n现在下载安装包？',
                                      QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if choice == QMessageBox.Yes and self.idle():
            self.release = release
            self.show_progress(0)
            self.start('download', lambda: updater.download_installer(release, self.cancel, self.download_progress.emit))

    def show_progress(self, percent):
        self.button.setText(f'下载更新 {percent}%')

    def ask_install(self):
        choice = QMessageBox.question(self.window, '安装更新', '安装包已通过 SHA256 校验。现在退出程序并打开安装向导？',
                                      QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if choice == QMessageBox.Yes and self.idle() and self.window.confirm_connection_action(exiting=True):
            self.install_pending = True
            self.window.begin_exit()

    def launch_pending(self):
        if self.install_pending:
            self.install_pending = False
            updater.launch_installer(self.installer)
            self.installer_started = True

    def remove_download(self):
        if self.installer and not self.installer_started:
            try:
                self.installer.unlink(missing_ok=True)
                self.installer.parent.rmdir()
            except OSError:
                pass
            self.installer = None

    def stop(self):
        self.cancel.set()
        self.startup.stop()
        self.daily.stop()
        self.remove_download()
