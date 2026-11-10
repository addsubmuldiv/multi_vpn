"""Fetch and verify installers published by the project's GitHub workflow."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

import certifi


REPOSITORY = 'addsubmuldiv/multi_vpn'
LATEST = f'https://api.github.com/repos/{REPOSITORY}/releases/latest'
DOWNLOAD = f'https://github.com/{REPOSITORY}/releases/download'
RELEASE_HOSTS = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com',
                 'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}
MAX_INSTALLER_BYTES = 512 * 1024 * 1024


class UpdateError(Exception):
    pass


@dataclass(frozen=True)
class ReleaseInstaller:
    version: str
    name: str
    url: str
    size: int
    sha256: str


class ReleaseRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if (target.scheme != 'https' or target.hostname not in RELEASE_HOSTS
                or target.port not in (None, 443) or target.username is not None):
            raise UpdateError('GitHub 返回了无法信任的下载地址。')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,9}\.\d{1,9}\.\d{1,9}', value):
        raise UpdateError('无法识别发布版本号。')
    return tuple(map(int, value.split('.')))


def installer_name(version, system=None, machine=None):
    system = sys.platform if system is None else system
    machine = platform.machine().lower() if machine is None else machine.lower()
    if system == 'win32' and machine in {'amd64', 'x86_64', 'arm64', 'aarch64'}:
        return f'MultiVPN-{version}-windows-x64-setup.exe'
    if system == 'darwin' and machine in {'arm64', 'x86_64'}:
        return f'MultiVPN-{version}-macos-{machine}.pkg'
    raise UpdateError('当前系统或架构没有可用的安装包。')


def select_installer(release, current_version):
    if release.get('draft') or release.get('prerelease'):
        return None
    tag = release.get('tag_name')
    if not isinstance(tag, str) or not tag.startswith('v'):
        raise UpdateError('无法识别 GitHub 发布标签。')
    version = tag[1:]
    if version_tuple(version) <= version_tuple(current_version):
        return None
    name = installer_name(version)
    url = f'{DOWNLOAD}/{tag}/{name}'
    matches = [asset for asset in release.get('assets', []) if asset.get('name') == name]
    if len(matches) != 1 or matches[0].get('state') != 'uploaded':
        raise UpdateError('此版本的安装包尚未发布。')
    asset = matches[0]
    size, digest = asset.get('size'), asset.get('digest')
    if (type(size) is not int or not 0 < size <= MAX_INSTALLER_BYTES
            or not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-fA-F0-9]{64}', digest)
            or asset.get('browser_download_url') != url):
        raise UpdateError('安装包的大小、地址或校验信息无效。')
    return ReleaseInstaller(version, name, url, size, digest[7:].lower())


def release_tls_context():
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=certifi.where())
    return context


def open_release_url(url, accept):
    request = Request(url, headers={'Accept': accept, 'User-Agent': 'MultiVPN-Updater'})
    handler = HTTPSHandler(context=release_tls_context())
    return build_opener(ReleaseRedirects(), handler).open(request, timeout=15)


def check_update(current_version):
    with open_release_url(LATEST, 'application/vnd.github+json') as response:
        payload = response.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise UpdateError('GitHub 发布信息超出大小限制。')
    return select_installer(json.loads(payload), current_version)


def download_installer(release, cancel, progress):
    # Installed Windows builds are elevated. Stage in their installation
    # directory to inherit its permissions before executing the installer.
    parent = Path(sys.executable).parent if sys.platform == 'win32' and getattr(sys, 'frozen', False) else None
    staging = Path(tempfile.mkdtemp(prefix='MultiVPN-update-', dir=parent))
    partial = staging / 'download.part'
    destination = staging / release.name
    digest = hashlib.sha256()
    received = 0
    percent = -1
    try:
        with open_release_url(release.url, 'application/octet-stream') as response, partial.open('xb') as output:
            while not cancel.is_set():
                chunk = response.read(128 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > release.size:
                    raise UpdateError('下载内容超出安装包大小。')
                digest.update(chunk)
                output.write(chunk)
                current = 100 * received // release.size
                if current != percent:
                    percent = current
                    progress(percent)
        if cancel.is_set():
            raise UpdateError('已取消下载。')
        if received != release.size or digest.hexdigest() != release.sha256:
            raise UpdateError('安装包 SHA256 或文件大小校验失败，请重新下载。')
        partial.rename(destination)
        return destination
    except BaseException:
        partial.unlink(missing_ok=True)
        staging.rmdir()
        raise


def launch_installer(package):
    if sys.platform == 'win32':
        os.startfile(str(package), 'runas')
    elif sys.platform == 'darwin':
        subprocess.run(['/usr/bin/open', '-a', 'Installer', str(package)], check=True, timeout=10)
    else:
        raise UpdateError('当前平台无法启动安装程序。')
