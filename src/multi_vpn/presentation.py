"""Shared connection labels, colors and runtime icons for the Qt interface."""
from dataclasses import dataclass
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap


@dataclass(frozen=True)
class Appearance:
    title: str
    button: str
    color: str
    background: str
    mark: str


STATES = {
    'disconnected': Appearance('未连接', '连接', '#64748b', '#f1f5f9', ''),
    'connecting': Appearance('连接中…', '连接中…', '#2563eb', '#eff6ff', '…'),
    'certificate': Appearance('等待证书确认', '等待验证…', '#a16207', '#fffbeb', '!'),
    'sms': Appearance('等待短信验证', '等待验证…', '#a16207', '#fffbeb', '!'),
    'connected': Appearance('已连接', '已连接', '#15803d', '#f0fdf4', '✓'),
    'degraded': Appearance('链路异常', '链路异常', '#a16207', '#fffbeb', '!'),
    'disconnecting': Appearance('断开中…', '断开中…', '#64748b', '#f1f5f9', '…'),
    'failed': Appearance('连接失败', '重新连接', '#b91c1c', '#fef2f2', '×'),
    'interrupted': Appearance('连接中断', '重新连接', '#b91c1c', '#fef2f2', '×'),
}


def state_icon(state):
    appearance = STATES[state]
    pixmap = QPixmap(48, 48)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(appearance.color))
    painter.drawEllipse(QRectF(3, 3, 42, 42))
    painter.setPen(QPen(QColor('white'), 4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if appearance.mark == '✓':
        painter.drawLine(13, 24, 21, 32)
        painter.drawLine(21, 32, 35, 16)
    elif appearance.mark == '×':
        painter.drawLine(16, 16, 32, 32)
        painter.drawLine(32, 16, 16, 32)
    elif appearance.mark == '!':
        painter.drawLine(24, 13, 24, 26)
        painter.drawPoint(24, 34)
    elif appearance.mark == '…':
        for x in (14, 24, 34):
            painter.drawPoint(x, 24)
    painter.end()
    icon = QIcon()
    icon.addPixmap(pixmap, QIcon.Normal)
    icon.addPixmap(pixmap, QIcon.Disabled)
    return icon


def badged_icon(base, state, icons):
    pixmap = base.pixmap(64, 64)
    if pixmap.isNull():
        return icons[state]
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor('white'))
    painter.drawEllipse(QRectF(36, 36, 28, 28))
    painter.drawPixmap(38, 38, 24, 24, icons[state].pixmap(48, 48))
    painter.end()
    return QIcon(pixmap)


def set_state(widget, state):
    if widget.property('state') != state:
        widget.setProperty('state', state)
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()


STYLE = '''
    QWidget { font-size: 14px; }
    QMainWindow { background: #f4f6fa; }
    QLabel#title { font-size: 28px; font-weight: 700; color: #17243a; }
    QLabel#heading { font-size: 22px; font-weight: 600; }
    QLabel#connectionStatus { font-size: 23px; font-weight: 700; }
    QLabel#statusDetail, QLabel#duration { color: #475569; }
    QLabel#summary { font-weight: 600; padding: 6px 10px; border-radius: 6px; }
    QWidget#statusPanel { border: 1px solid #d5dce7; border-radius: 8px; }
    QPushButton { padding: 9px 16px; border: 1px solid #cbd3df; border-radius: 6px; background: white; }
    QPushButton:disabled { color: #94a3b8; background: #e8edf3; }
    QPushButton#primary { background: #2563eb; color: white; border-color: #2563eb; font-weight: 600; }
    QPushButton#primary:hover { background: #1d4ed8; }
    QPushButton#primary:disabled { background: #e2e8f0; color: #475569; border-color: #cbd3df; }
    QPushButton#exitButton { background: transparent; border: none; color: #64748b; padding: 6px 10px; }
    QPushButton#exitButton:hover { background: #fef2f2; color: #b91c1c; }
    QProgressBar { border: none; background: #dbeafe; border-radius: 2px; }
    QProgressBar::chunk { background: #2563eb; }
    QLineEdit,QSpinBox,QListWidget,QPlainTextEdit { background: white; border: 1px solid #d5dce7; border-radius: 5px; padding: 7px; }
    QListWidget::item { padding: 12px 4px; }
    QListWidget::item:selected { background: #dbe9ff; color: #153b77; }
'''
for name, appearance in STATES.items():
    STYLE += f'''
        QWidget#statusPanel[state="{name}"] {{ background: {appearance.background}; border-color: {appearance.color}; }}
        QLabel#connectionStatus[state="{name}"] {{ color: {appearance.color}; }}
        QLabel#summary[state="{name}"] {{ color: {appearance.color}; background: {appearance.background}; }}
    '''
    if name in {'connected', 'degraded', 'connecting', 'sms', 'certificate'}:
        STYLE += f'''
            QPushButton#primary[state="{name}"]:disabled {{ background: {appearance.color}; color: white; border-color: {appearance.color}; }}
        '''
