"""Offline native adapter acceptance. No gateway, credentials or VPN login."""
import time,uuid
from multi_vpn.platforms.windows import WindowsAdapter,powershell,address_ready_script,require_address_ready

names=['MultiVPN-CI-'+uuid.uuid4().hex[:8] for _ in range(2)]
adapters=[]
try:
    for name,vip in zip(names,['192.0.2.8','192.0.2.9']):
        adapter=WindowsAdapter(name,vip,[],[])
        adapters.append(adapter)
        require_address_ready(powershell(address_ready_script(adapter.index,vip,timeout=0)),vip)
    assert adapters[0].index!=adapters[1].index
    print('Two independent native adapters reached Preferred without any VPN login')
finally:
    for adapter in reversed(adapters):adapter.close()
deadline=time.monotonic()+15
while True:
    present=powershell("Get-NetAdapter -Name '"+"','".join(names)+"' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name")
    if not present:break
    if time.monotonic()>=deadline:raise RuntimeError('Test adapter cleanup did not finish')
    time.sleep(.25)
print('Both test adapters cleaned up')
