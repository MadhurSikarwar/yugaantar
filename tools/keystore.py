"""OS keystore for key-encryption keys: Windows DPAPI (CryptProtectData), bound to the user account.

Used by the deployment layer (``tools/bridge.py``) to keep the backup vault's encryption key out of
a plain file: the vault stores only the DPAPI-protected blob, which only the same Windows user on
the same machine can unwrap. This lives in ``tools/`` because it needs ``ctypes``, which the
project's static check forbids in ``t4/`` (the judged runtime); ``t4.backup`` receives plain
wrap/unwrap callables and never imports it.

Not covered: Linux and macOS (no provider here: ``available()`` is False and secure mode refuses
to run), TPM or HSM wrapping, and an attacker who runs code as the same Windows user (DPAPI then
unwraps for them too). Python cannot reliably erase the unwrapped key from memory.
"""
from __future__ import annotations

import os

_ENTROPY = b"latticelock-vault-key-v1"


def available() -> bool:
    return os.name == "nt"


def _dpapi():
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return ctypes, Blob, crypt32, kernel32


def _call(function_name: str, data: bytes) -> bytes:
    if not available():
        raise OSError("no OS keystore on this platform")
    ctypes, Blob, crypt32, kernel32 = _dpapi()
    buffer_in = ctypes.create_string_buffer(data, len(data))
    entropy_buf = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
    blob_in = Blob(len(data), ctypes.cast(buffer_in, ctypes.POINTER(ctypes.c_char)))
    entropy = Blob(len(_ENTROPY), ctypes.cast(entropy_buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = Blob()
    function = getattr(crypt32, function_name)
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    # Both calls share this shape: (in, description, entropy, reserved, prompt, flags, out).
    ok = function(ctypes.byref(blob_in), None, ctypes.byref(entropy), None, None,
                  CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise OSError("the OS keystore refused the operation")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def wrap(key: bytes) -> bytes:
    """Protect ``key`` for the current Windows user (DPAPI)."""
    return _call("CryptProtectData", key)


def unwrap(blob: bytes) -> bytes:
    """Recover a key protected by ``wrap`` (same user, same machine). Raises OSError otherwise."""
    return _call("CryptUnprotectData", blob)
