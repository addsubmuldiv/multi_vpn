"""Exercise the actual PowerShell readiness check with a synthetic provider.

No adapters, addresses, routes or VPN connections are created by these tests.
"""
import json,sys
import pytest
from multi_vpn.platforms.windows import address_ready_script,require_address_ready

def probe(rows):
    if sys.platform!='win32':pytest.skip('Windows PowerShell required')
    from multi_vpn.platforms.windows import powershell
    objects=','.join("[pscustomobject]@{IPAddress='%s';AddressState='%s'}"%row for row in rows)
    provider='function Get-NetIPAddress { param($InterfaceIndex,$AddressFamily,$IPAddress,$ErrorAction) @('+objects+') };'
    return powershell(provider+address_ready_script(123,'192.0.2.8',timeout=0))

def test_preferred_assigned_ip_with_unusable_apipa_is_ready():
    result=probe([('192.0.2.8','Preferred'),('169.254.1.2','Tentative')])
    require_address_ready(result,'192.0.2.8')

def test_other_preferred_address_cannot_mask_unready_assigned_ip():
    result=probe([('192.0.2.8','Tentative'),('169.254.1.2','Preferred')])
    assert json.loads(result)=={'ready':False,'state':'Tentative'}
    with pytest.raises(RuntimeError,match='仍在确认地址'):require_address_ready(result,'192.0.2.8')

def test_duplicate_is_an_error_not_a_success():
    result=probe([('192.0.2.8','Duplicate')])
    with pytest.raises(RuntimeError,match='地址冲突'):require_address_ready(result,'192.0.2.8')

def test_missing_assigned_address_is_an_error():
    result=probe([('169.254.1.2','Preferred')])
    with pytest.raises(RuntimeError,match='未找到'):require_address_ready(result,'192.0.2.8')
