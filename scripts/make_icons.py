"""Render the editable vector master and encode native application icon formats."""
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage,QPainter
from PySide6.QtSvg import QSvgRenderer
from PIL import Image

root=Path(__file__).resolve().parents[1]
assets=root/'assets'
image=QImage(1024,1024,QImage.Format_ARGB32)
image.fill(Qt.transparent)
painter=QPainter(image)
QSvgRenderer(str(assets/'icon.svg')).render(painter)
painter.end()
if not image.save(str(assets/'icon.png')):raise RuntimeError('PNG export failed')
with Image.open(assets/'icon.png') as source:
    source.save(assets/'icon.ico',sizes=[(s,s) for s in (16,24,32,48,64,128,256)])
    source.save(assets/'icon.icns')
print('Created PNG, ICO and ICNS from assets/icon.svg')
