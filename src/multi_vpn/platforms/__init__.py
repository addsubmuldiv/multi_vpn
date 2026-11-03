import sys

def create_adapter(name, vip, routes, dns=()):
    if sys.platform == 'win32':
        from .windows import WindowsAdapter
        return WindowsAdapter(name, vip, routes, dns)
    if sys.platform == 'darwin':
        from .macos import MacAdapter
        return MacAdapter(name, vip, routes, dns)
    raise RuntimeError('目前支持 Windows 和 macOS')
