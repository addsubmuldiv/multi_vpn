"""Copy upstream notices from the build environment into the installer."""
from importlib import metadata
from pathlib import Path
import shutil,sys

root=Path(__file__).resolve().parents[1]
destination=root/'build'/'third-party-licenses'
destination.mkdir(parents=True,exist_ok=True)
for file in (root/'licenses').glob('*.txt'):
    shutil.copy2(file,destination/file.name)
components=[]
for dist in metadata.distributions():
    name=dist.metadata.get('Name','unknown')
    components.append(f'{name} {dist.version}')
    for file in dist.files or []:
        if any(x in str(file).lower() for x in ('/licenses/','/license','/copying')):
            source=Path(dist.locate_file(file))
            if not source.is_file():continue
            target=destination/name/source.name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)
python_license=Path(sys.base_prefix)/'LICENSE.txt'
if not python_license.exists():
    candidates=list(Path(sys.base_prefix).glob('**/Resources/Python.app/Contents/Resources/English.lproj/Documentation/LICENSE*'))
    if candidates:python_license=candidates[0]
if python_license.exists():shutil.copy2(python_license,destination/'Python-LICENSE.txt')
(destination/'COMPONENTS.txt').write_text('\n'.join(sorted(components))+'\n',encoding='utf-8')
print('Collected upstream component versions and licenses')
