"""Cancellable setup I/O; TLS sockets remain owned by the session thread."""
from contextlib import contextmanager
from contextvars import ContextVar
import errno
import queue
import select
import socket
import ssl
import subprocess
import threading
import time


class Cancelled(Exception):
    pass


_cancel = ContextVar('setup_cancel', default=None)
POLL_INTERVAL = .1


@contextmanager
def cancellation(event):
    token = _cancel.set(event)
    try:
        yield
    finally:
        _cancel.reset(token)


def check_cancelled():
    event = _cancel.get()
    if event is not None and event.is_set():
        raise Cancelled()


def is_cancellable():
    return _cancel.get() is not None


def wait_ready(sock, writing, deadline):
    while True:
        check_cancelled()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('网络操作超时')
        readable, writable, exceptional = select.select(
            [] if writing else [sock], [sock] if writing else [], [sock],
            min(POLL_INTERVAL, remaining))
        if readable or writable or exceptional:
            return


def resolve(host, port, timeout=12, family=socket.AF_UNSPEC):
    if _cancel.get() is None:
        return socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    check_cancelled()
    # OS DNS resolution has no portable cancellation API. Only its result is
    # detached on cancellation; this worker never opens a socket or adapter.
    result = queue.Queue(maxsize=1)
    def lookup():
        try:
            result.put((socket.getaddrinfo(host, port, family, socket.SOCK_STREAM), None))
        except Exception as exc:
            result.put((None, exc))
    threading.Thread(target=lookup, daemon=True, name='vpn-dns').start()
    deadline = time.monotonic() + timeout
    while True:
        check_cancelled()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('DNS 解析超时')
        try:
            addresses, error = result.get(timeout=min(POLL_INTERVAL, remaining))
        except queue.Empty:
            continue
        check_cancelled()
        if error:
            raise error
        return addresses


def connect_socket(host, port, timeout):
    if _cancel.get() is None:
        return socket.create_connection((host, port), timeout=timeout)
    deadline = time.monotonic() + timeout
    addresses = resolve(host, port, timeout)
    error = OSError('网关没有可用地址')
    for family, kind, protocol, _, address in addresses:
        check_cancelled()
        if time.monotonic() >= deadline:
            raise TimeoutError('连接网关超时')
        sock = socket.socket(family, kind, protocol)
        try:
            sock.setblocking(False)
            status = sock.connect_ex(address)
            if status not in (0, errno.EISCONN, 10056):
                if status not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                                  10035, 10036, 10037):
                    raise OSError(status, '连接网关失败')
                wait_ready(sock, True, deadline)
                status = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if status:
                    raise OSError(status, '连接网关失败')
            check_cancelled()
            return sock
        except OSError as exc:
            error = exc
            sock.close()
        except BaseException:
            sock.close()
            raise
    raise error


class CancellableSocket:
    """Nonblocking socket with cancellable blocking operations during setup.

    setblocking(False) hands retries back to the forwarding loop unchanged.
    """
    def __init__(self, sock, timeout):
        self.socket = sock
        self.timeout = timeout
        sock.setblocking(False)

    def __getattr__(self, name):
        return getattr(self.socket, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.socket.close()

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def setblocking(self, blocking):
        self.timeout = None if blocking else 0

    def _deadline(self):
        return float('inf') if self.timeout is None else time.monotonic() + self.timeout

    def _call(self, operation, *args, deadline=None, writing=False):
        if self.timeout == 0:
            return operation(*args)
        deadline = self._deadline() if deadline is None else deadline
        while True:
            check_cancelled()
            if time.monotonic() >= deadline:
                raise TimeoutError('网络操作超时')
            try:
                return operation(*args)
            except ssl.SSLWantReadError:
                wait_ready(self.socket, False, deadline)
            except ssl.SSLWantWriteError:
                wait_ready(self.socket, True, deadline)
            except BlockingIOError:
                wait_ready(self.socket, writing, deadline)

    def do_handshake(self):
        return self._call(self.socket.do_handshake)

    def recv(self, size):
        return self._call(self.socket.recv, size)

    def recvmsg(self, size, ancillary_size):
        return self._call(self.socket.recvmsg, size, ancillary_size)

    def send(self, data):
        return self._call(self.socket.send, data, writing=True)

    def sendall(self, data):
        deadline = self._deadline()
        remaining = memoryview(data)
        while remaining:
            sent = self._call(self.socket.send, remaining, deadline=deadline, writing=True)
            if not sent:
                raise ConnectionError('网关已关闭连接')
            remaining = remaining[sent:]


def run_process(args, *, timeout, capture_output=False, check=False, **kwargs):
    if _cancel.get() is None:
        return subprocess.run(args, timeout=timeout, capture_output=capture_output,
                              check=check, **kwargs)
    check_cancelled()
    if capture_output:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process = subprocess.Popen(args, **kwargs)
    deadline = time.monotonic() + timeout
    try:
        while True:
            check_cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(POLL_INTERVAL, remaining))
                break
            except subprocess.TimeoutExpired:
                pass
        result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result
    except BaseException:
        process.terminate()
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=1)
        raise
