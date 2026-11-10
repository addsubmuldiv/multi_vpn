"""Per-session AES-CBC key schedules from public system crypto APIs."""

import ctypes as c
from functools import lru_cache
import sys
from weakref import finalize


BLOCK = 16
MAX_PACKET = 65536
PTR = c.c_void_p
ULONG = c.c_uint32
SIZE = c.c_size_t


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


def check(status):
    if status:
        raise OSError('Native AES-CBC operation failed')


@lru_cache(maxsize=1)
def cng():
    library = c.WinDLL('bcrypt.dll')
    status = c.c_int32
    return (
        bind(library, 'BCryptOpenAlgorithmProvider', status, c.POINTER(PTR), c.c_wchar_p, c.c_wchar_p, ULONG),
        bind(library, 'BCryptSetProperty', status, PTR, c.c_wchar_p, PTR, ULONG, ULONG),
        bind(library, 'BCryptGenerateSymmetricKey', status, PTR, c.POINTER(PTR), PTR, ULONG, PTR, ULONG, ULONG),
        bind(library, 'BCryptEncrypt', status, PTR, PTR, ULONG, PTR, PTR, ULONG, PTR, ULONG, c.POINTER(ULONG), ULONG),
        bind(library, 'BCryptDecrypt', status, PTR, PTR, ULONG, PTR, PTR, ULONG, PTR, ULONG, c.POINTER(ULONG), ULONG),
        bind(library, 'BCryptDestroyKey', status, PTR),
        bind(library, 'BCryptCloseAlgorithmProvider', status, PTR, ULONG),
    )


def release_cng(destroy, close, key, provider):
    if key.value:
        destroy(key)
    close(provider, 0)


class CngCBC:
    def __init__(self, key):
        open_provider, set_property, make_key, self.encrypt, self.decrypt, destroy, close = cng()
        provider, self.key = PTR(), PTR()
        check(open_provider(c.byref(provider), 'AES', None, 0))
        self.release = finalize(self, release_cng, destroy, close, self.key, provider)
        try:
            cbc = 'ChainingModeCBC\0'.encode('utf-16-le')
            check(set_property(provider, 'ChainingMode', cbc, len(cbc), 0))
            check(make_key(provider, c.byref(self.key), None, 0, key, len(key), 0))
            self.iv = c.create_string_buffer(BLOCK)
            self.output = c.create_string_buffer(MAX_PACKET)
            self.written = ULONG()
            self.written_ref = c.byref(self.written)
        except BaseException:
            self.release()
            raise

    def transform(self, data, iv, decrypt):
        operation = self.decrypt if decrypt else self.encrypt
        # BCrypt mutates the IV buffer. Copy each datagram's IV before use.
        c.memmove(self.iv, iv, BLOCK)
        check(operation(self.key, data, len(data), None, self.iv, BLOCK,
                        self.output, len(data), self.written_ref, 0))
        if self.written.value != len(data):
            raise OSError('Unexpected native AES-CBC output length')
        return c.string_at(self.output, self.written.value)


@lru_cache(maxsize=1)
def common_crypto():
    library = c.CDLL('/usr/lib/libSystem.B.dylib')
    status = c.c_int32
    return (
        bind(library, 'CCCryptorCreate', status, ULONG, ULONG, ULONG, PTR, SIZE, PTR, c.POINTER(PTR)),
        bind(library, 'CCCryptorReset', status, PTR, PTR),
        bind(library, 'CCCryptorUpdate', status, PTR, PTR, SIZE, PTR, SIZE, c.POINTER(SIZE)),
        bind(library, 'CCCryptorRelease', status, PTR),
    )


def release_common(release, handles):
    for handle in handles:
        if handle.value:
            release(handle)


class CommonCryptoCBC:
    def __init__(self, key):
        create, self.reset, self.update, release = common_crypto()
        self.handles = PTR(), PTR()
        self.release = finalize(self, release_common, release, self.handles)
        try:
            for direction, handle in enumerate(self.handles):
                # kCCAlgorithmAES=0, and options=0 selects CBC without padding.
                check(create(direction, 0, 0, key, len(key), bytes(BLOCK), c.byref(handle)))
            self.output = c.create_string_buffer(MAX_PACKET)
            self.written = SIZE()
            self.written_ref = c.byref(self.written)
        except BaseException:
            self.release()
            raise

    def transform(self, data, iv, decrypt):
        handle = self.handles[decrypt]
        check(self.reset(handle, iv))
        check(self.update(handle, data, len(data), self.output, len(data), self.written_ref))
        if self.written.value != len(data):
            raise OSError('Unexpected native AES-CBC output length')
        return c.string_at(self.output, self.written.value)


def native_cbc(key):
    if sys.platform == 'win32':
        return CngCBC(key)
    if sys.platform == 'darwin':
        return CommonCryptoCBC(key)
    return None
