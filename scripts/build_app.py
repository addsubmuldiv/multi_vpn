"""Build on the target OS; no private configuration is collected."""
import argparse,platform,subprocess,sys
from pathlib import Path

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--version',default='0.1.0');args=parser.parse_args()
command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--windowed','--onedir',
         '--name','MultiVPN','--paths',str(root/'src'),
         '--collect-submodules','keyring.backends',
         '--add-data',f'{root / "assets"}:assets']
if sys.platform=='win32':
    command+=['--icon',str(root/'assets/icon.ico'),'--uac-admin',
              '--add-binary',f'{root / "vendor/wintun.dll"}:vendor',
              '--add-data',f'{root / "vendor/WINTUN-LICENSE.txt"}:vendor']
elif sys.platform=='darwin':
    if platform.machine()!='arm64':raise RuntimeError('Build Apple Silicon release on native arm64')
    command+=['--icon',str(root/'assets/icon.icns'),'--target-arch','arm64',
              '--osx-bundle-identifier','io.github.addsubmuldiv.multivpn']
else:raise RuntimeError('Build on Windows or macOS')
command.append(str(root/'scripts/frozen_entry.py'))
subprocess.run(command,cwd=root,check=True)
