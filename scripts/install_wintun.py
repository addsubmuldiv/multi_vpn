"""Fetch the signed upstream Wintun binary, verify the archive, select architecture."""
import hashlib,pathlib,platform,urllib.request,zipfile,io
root=pathlib.Path(__file__).resolve().parents[1]
data=urllib.request.urlopen('https://www.wintun.net/builds/wintun-0.14.1.zip',timeout=60).read()
if hashlib.sha256(data).hexdigest()!='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51':raise RuntimeError('Archive checksum mismatch')
arch='arm64' if platform.machine().lower() in ('arm64','aarch64') else 'amd64'
with zipfile.ZipFile(io.BytesIO(data)) as z:
    target=root/'vendor';target.mkdir(exist_ok=True)
    (target/'wintun.dll').write_bytes(z.read(f'wintun/bin/{arch}/wintun.dll'))
    (target/'WINTUN-LICENSE.txt').write_bytes(z.read('wintun/LICENSE.txt'))
print('Installed verified Wintun 0.14.1:',arch)
