from datetime import datetime
from hashlib import sha256
from io import BytesIO
from threading import Event
from urllib.request import Request

import pytest

from multi_vpn import updater
from multi_vpn.update_ui import next_daily_check


@pytest.mark.parametrize(('system', 'machine', 'suffix'), [
    ('win32', 'AMD64', 'windows-x64-setup.exe'),
    ('darwin', 'arm64', 'macos-arm64.pkg'),
    ('darwin', 'x86_64', 'macos-x86_64.pkg'),
])
def test_only_newer_release_with_expected_platform_asset_is_selected(monkeypatch, system, machine, suffix):
    monkeypatch.setattr(updater.sys, 'platform', system)
    monkeypatch.setattr(updater.platform, 'machine', lambda: machine)
    name = f'MultiVPN-0.2.10-{suffix}'
    url = f'{updater.DOWNLOAD}/v0.2.10/{name}'
    asset = dict(name=name, browser_download_url=url, size=123, state='uploaded', digest='sha256:' + 'a' * 64)
    release = dict(tag_name='v0.2.10', assets=[asset])
    assert updater.select_installer(release, '0.2.9') == updater.ReleaseInstaller('0.2.10', name, url, 123, 'a' * 64)
    assert updater.select_installer(release, '0.2.10') is None
    assert updater.select_installer(release, '0.3.0') is None
    assert updater.select_installer(dict(release, prerelease=True), '0.2.9') is None
    asset['browser_download_url'] = 'https://example.test/installer'
    with pytest.raises(updater.UpdateError, match='地址'):
        updater.select_installer(release, '0.2.9')


@pytest.mark.parametrize('target', ['http://github.com/file', 'https://github.com.example.test/file'])
def test_download_redirect_requires_trusted_https_host(target):
    with pytest.raises(updater.UpdateError):
        updater.ReleaseRedirects().redirect_request(Request(updater.DOWNLOAD), None, 302, '', {}, target)


@pytest.mark.parametrize('failure', [None, 'digest', 'size', 'cancel'])
def test_only_verified_download_becomes_an_installer(tmp_path, monkeypatch, failure):
    payload = b'synthetic installer bytes'
    expected_digest = sha256(payload).hexdigest() if failure != 'digest' else '0' * 64
    size = len(payload) + (1 if failure == 'size' else 0)
    release = updater.ReleaseInstaller('0.2.4', 'setup.exe', updater.DOWNLOAD, size, expected_digest)
    monkeypatch.setattr(updater, 'open_release_url', lambda *args: BytesIO(payload))
    monkeypatch.setattr(updater.tempfile, 'tempdir', str(tmp_path))
    cancel = Event()
    if failure == 'cancel':
        cancel.set()
    if failure:
        with pytest.raises(updater.UpdateError):
            updater.download_installer(release, cancel, lambda value: None)
        assert not list(tmp_path.iterdir())
    else:
        progress = []
        package = updater.download_installer(release, cancel, progress.append)
        assert package.read_bytes() == payload
        assert progress == [100]
        assert list(package.parent.iterdir()) == [package]


def test_daily_check_is_anchored_to_ten_in_local_time():
    assert next_daily_check(datetime(2026, 11, 10, 9, 59)) == datetime(2026, 11, 10, 10)
    assert next_daily_check(datetime(2026, 11, 10, 10)) == datetime(2026, 11, 11, 10)
