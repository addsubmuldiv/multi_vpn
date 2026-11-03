import threading,pytest
from multi_vpn.model import RouteRegistry
from multi_vpn.session import routes_for

def test_conflicting_sessions_and_release():
    registry=RouteRegistry();registry.acquire('one',['10.0.0.0/8'])
    with pytest.raises(RuntimeError):registry.acquire('two',['10.1.0.0/16'])
    registry.acquire('two',['192.0.2.0/24']);registry.release('one')
    registry.acquire('three',['10.1.0.0/16'])

def test_gateway_is_excluded_without_changing_default_route():
    routes=routes_for({'route_type':1,'expansion_routes':['192.0.2.0/24']},'192.0.2.10')
    import ipaddress
    assert not any(ipaddress.IPv4Address('192.0.2.10') in ipaddress.IPv4Network(r) for r in routes)
    assert any(ipaddress.IPv4Address('192.0.2.11') in ipaddress.IPv4Network(r) for r in routes)

def test_excluded_networks():
    routes=routes_for({'route_type':1,'expansion_routes':['10.0.0.0/8'],'exclude_routes':['10.2.0.0/16']},'192.0.2.1')
    import ipaddress
    assert not any(ipaddress.IPv4Address('10.2.0.1') in ipaddress.IPv4Network(r) for r in routes)

def test_reject_default_routes():
    with pytest.raises(RuntimeError):routes_for({'route_type':1,'expansion_routes':['0.0.0.0/0']},'192.0.2.1')
