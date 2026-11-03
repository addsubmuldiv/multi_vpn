import os,re
from importlib.metadata import version

ref=os.environ.get('GITHUB_REF','')
value=ref.removeprefix('refs/tags/v') if ref.startswith('refs/tags/v') else version('multi-vpn')
if not re.fullmatch(r'\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?',value):
    raise ValueError('Invalid release version')
print('APP_VERSION='+value)
