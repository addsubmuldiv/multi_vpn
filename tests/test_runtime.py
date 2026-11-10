import os
import subprocess
import sys
from multi_vpn.runtime import relaunch_args,resource_root

def test_frozen_relaunch_is_executable_not_python_module(tmp_path,monkeypatch):
    monkeypatch.setattr(sys,'frozen',True,raising=False)
    monkeypatch.setattr(sys,'_MEIPASS',str(tmp_path),raising=False)
    assert relaunch_args(tmp_path)==['--data-dir',str(tmp_path.resolve())]
    assert resource_root()==tmp_path

def test_source_relaunch_preserves_checkout_without_pythonpath(tmp_path,monkeypatch):
    monkeypatch.delattr(sys,'frozen',raising=False)
    args=relaunch_args(tmp_path)
    assert args[-2:]==['--data-dir',str(tmp_path.resolve())]
    env=dict(os.environ)
    env.pop('PYTHONPATH',None)
    subprocess.run([sys.executable,*args,'--help'],cwd=tmp_path,env=env,
                   check=True,capture_output=True,timeout=15)
