import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
def test_gui_starts_without_network(tmp_path,monkeypatch):
    import multi_vpn.model as model
    monkeypatch.setattr(model,'config_dir',lambda:tmp_path)
    from PySide6.QtWidgets import QApplication
    from multi_vpn.app import Window
    app=QApplication.instance() or QApplication([])
    window=Window();window.show();app.processEvents()
    assert window.windowTitle().startswith('Multi VPN · ')
    assert not window.connect_button.isEnabled()
    window.close()

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
    window.close()
