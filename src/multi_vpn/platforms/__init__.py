import sys

def validate_mtu(mtu):
    if type(mtu) is not int or not 576 <= mtu <= 1400:
        raise ValueError('隧道 MTU 必须介于 576 和 1400 字节')
    return mtu


def create_adapter(name, vip, routes, dns=(), mtu=1400):
    if sys.platform == 'win32':
        from .windows import WindowsAdapter
        return WindowsAdapter(name, vip, routes, dns, mtu)
    if sys.platform == 'darwin':
        from .macos import MacAdapter
        return MacAdapter(name, vip, routes, dns, mtu)
    raise RuntimeError('目前支持 Windows 和 macOS')
