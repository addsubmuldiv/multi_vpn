"""Build on the target OS; no private configuration is collected."""
import argparse,platform,subprocess,sys
from pathlib import Path

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--version',default='0.1.0');args=parser.parse_args()
subprocess.run([sys.executable,str(root/'scripts/collect_licenses.py')],check=True)
command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--windowed','--onedir',
         '--name','MultiVPN','--paths',str(root/'src'),
         '--collect-submodules','keyring.backends',
         '--add-data',f'{root / "assets"}:assets',
         '--add-data',f'{root / "build/third-party-licenses"}:licenses',
         '--add-data',f'{root / "THIRD_PARTY_NOTICES.md"}:.']
if sys.platform=='win32':
    command+=['--icon',str(root/'assets/icon.ico'),'--uac-admin',
              '--add-binary',f'{root / "vendor/wintun.dll"}:vendor',
              '--add-data',f'{root / "vendor/WINTUN-LICENSE.txt"}:vendor']
elif sys.platform=='darwin':
    arch=platform.machine()
    if arch not in ('arm64','x86_64'):raise RuntimeError('Unsupported macOS architecture: '+arch)
    command+=['--icon',str(root/'assets/icon.icns'),'--target-arch',arch,
              '--osx-bundle-identifier','io.github.addsubmuldiv.multivpn']
else:raise RuntimeError('Build on Windows or macOS')
command.append(str(root/'scripts/frozen_entry.py'))
subprocess.run(command,cwd=root,check=True)
