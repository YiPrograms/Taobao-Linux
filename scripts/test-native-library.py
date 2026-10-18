#!/usr/bin/env python3
"""Test the standalone C ABI inside the throwaway keyring from the shell suite."""

import ctypes
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if os.environ.get("TAOBAO_TEST_SECRET_SERVICE") != "1":
    raise SystemExit("Run through scripts/test-security-addon.sh to isolate the keyring")

data = Path(os.environ["TAOBAO_HOME"])
library = ctypes.CDLL(str(data / "native/security-bodyguard/libtaobao-security-linux.so"))
library.tb_security_abi_version.restype = ctypes.c_uint
library.tb_security_create.argtypes = [ctypes.c_char_p]
library.tb_security_create.restype = ctypes.c_void_p
library.tb_security_destroy.argtypes = [ctypes.c_void_p]
library.tb_security_request.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_void_p),
]
library.tb_security_free.argtypes = [ctypes.c_void_p]
assert library.tb_security_abi_version() == 1
assert library.tb_security_create(None) is None
assert library.tb_security_create(b"") is None


def request(context, value, expect_error=False):
    output = ctypes.c_void_p()
    data = value if isinstance(value, bytes) else json.dumps(value).encode()
    result = library.tb_security_request(context, data, ctypes.byref(output))
    assert output.value
    try:
        parsed = json.loads(ctypes.string_at(output))
    finally:
        library.tb_security_free(output)
    assert (result < 0) == expect_error, parsed.get("error", "unexpected C ABI result")
    return parsed


parameters = {
    "api": "example.invalid/c-abi",
    "urlmd5": "900150983cd24fb0d6963f7d28e17f72",
    "timestamp": "1792288800",
}
namespace = f"c-abi-concurrent-{os.getpid()}".encode()


def independently_initialize(_):
    context = library.tb_security_create(namespace)
    assert context
    try:
        assert request(context, {"operation": "status"})["status"]["initialized"] is False
        request(context, b"{malformed", expect_error=True)
        request(
            context,
            {"operation": "getSecurityFactors", "parameters": parameters},
            expect_error=True,
        )
        initialized = request(context, {"operation": "initialize"})
        assert initialized["success"] is True
        assert initialized["status"]["serverEnrolled"] is False
        assert initialized["status"]["serverAcceptance"] == "unverified"
        result = request(context, {"operation": "getSecurityFactors", "parameters": parameters})
        assert result["success"] is True
        headers = json.loads(result["result"])
        identity = headers["pctb-x-umt"]
        assert len(identity) == 32
        assert headers["pctb-x-mini-wua"]
        assert headers["pctb-x-sign"]
        assert request(context, {"operation": "cleanup"})["status"]["initialized"] is False
        request(
            context,
            {"operation": "getSecurityFactors", "parameters": parameters},
            expect_error=True,
        )
        return identity
    finally:
        library.tb_security_destroy(context)


# Four independent contexts race the initial lookup/create/store. Linux flock
# must prevent multiple persistent local device identities in one namespace.
with ThreadPoolExecutor(max_workers=4) as executor:
    identities = list(executor.map(independently_initialize, range(4)))
assert len(set(identities)) == 1
print(
    json.dumps(
        {
            "cAbiVersion": 1,
            "concurrentContexts": 4,
            "identityPersistence": "passed",
            "serverAcceptance": "unverified",
        }
    )
)
