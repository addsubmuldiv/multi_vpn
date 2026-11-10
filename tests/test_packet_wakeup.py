import select
import sys

import pytest

from multi_vpn.platforms import validate_mtu


def test_mtu_validation():
    assert validate_mtu(1400) == 1400
    assert validate_mtu(1300) == 1300
    for invalid in (575, 1401, 1300.0, '1300'):
        with pytest.raises(ValueError):
            validate_mtu(invalid)


@pytest.mark.skipif(sys.platform != 'win32', reason='requires a Windows event handle')
def test_wintun_wait_handle_wakes_socket_and_can_close_while_signaled():
    import ctypes as c
    from ctypes import wintypes as w

    from multi_vpn.platforms.windows import PacketWakeup

    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
    kernel.CreateEventW.restype = w.HANDLE
    kernel.SetEvent.argtypes = [w.HANDLE]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    event = kernel.CreateEventW(None, False, False, None)
    assert event
    try:
        wakeup = PacketWakeup(event)
        try:
            for turn in range(3):
                assert kernel.SetEvent(event)
                assert select.select([wakeup.reader], [], [], 2)[0] == [wakeup.reader]
                if turn < 2:
                    wakeup.acknowledge()
                    assert not select.select([wakeup.reader], [], [], 0)[0]
        finally:
            wakeup.close()
        assert not wakeup.thread.is_alive()
    finally:
        kernel.CloseHandle(event)
