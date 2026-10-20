"""Protect secrets in the config file with Windows DPAPI (current-user scope).

Values are stored as ``dpapi:<base64>`` and can only be decrypted by the same Windows
user on the same machine. On other platforms values pass through unchanged.
"""
from __future__ import annotations

import base64
import sys

PREFIX = "dpapi:"

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _CRYPTPROTECT_UI_FORBIDDEN = 0x1

    def _call(fn, data: bytes) -> bytes:
        buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _Blob()
        if not fn(ctypes.byref(blob_in), None, None, None, None, _CRYPTPROTECT_UI_FORBIDDEN,
                  ctypes.byref(blob_out)):
            raise OSError(ctypes.GetLastError(), "DPAPI call failed")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(blob_out.pbData)

    def protect(value: str) -> str:
        if not value or value.startswith(PREFIX):
            return value
        out = _call(_crypt32.CryptProtectData, value.encode())
        return PREFIX + base64.b64encode(out).decode()

    def unprotect(value: str) -> str:
        if not value or not value.startswith(PREFIX):
            return value
        return _call(_crypt32.CryptUnprotectData, base64.b64decode(value[len(PREFIX):])).decode()

else:  # pragma: no cover - non-Windows
    def protect(value: str) -> str:
        return value

    def unprotect(value: str) -> str:
        if value and value.startswith(PREFIX):
            raise ValueError("DPAPI-protected value can only be read on the Windows account that saved it")
        return value
