import sys

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from multi_vpn.native_cbc import native_cbc


@pytest.mark.skipif(sys.platform not in ('win32', 'darwin'), reason='requires system AES-CBC')
def test_native_key_schedule_preserves_independent_iv_and_wire_bytes():
    key = bytes(range(16))
    native = native_cbc(key)
    try:
        for index, size in enumerate((16, 1392, 32, 16, 1392, 16)):
            iv = bytes([index]) * 16
            plaintext = bytes(i % 251 for i in range(size))
            reference = Cipher(algorithms.AES128(key), modes.CBC(iv)).encryptor()
            ciphertext = reference.update(plaintext) + reference.finalize()
            assert native.transform(plaintext, iv, False) == ciphertext
            assert native.transform(ciphertext, iv, True) == plaintext
    finally:
        native.release()
