#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import resource
import socket
import sys
from collections.abc import Sequence

PR_SET_NO_NEW_PRIVS = 38
SECCOMP_ACT_ALLOW = 0x7FFF0000
SECCOMP_ACT_ERRNO_BASE = 0x00050000
SCMP_CMP_EQ = 4


class ScmpArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


# CUDA/NVIDIA user-space libraries may require local AF_UNIX/AF_NETLINK IPC while
# enumerating devices. Blocking socket(2) globally breaks cudaGetDeviceCount().
# The security boundary therefore denies external/network-capable socket families
# at socket creation time, while allowing local kernel/UNIX IPC. Inherited file
# descriptors are closed before exec so the target cannot reuse a pre-opened IP fd.
# io_uring_setup is denied as an additional guard against alternate async network IO.
_NETWORK_SOCKET_FAMILY_NAMES = (
    "AF_INET",
    "AF_INET6",
    "AF_PACKET",
    "AF_RDS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_VSOCK",
    "AF_NFC",
    "AF_XDP",
    "AF_MCTP",
)
DENIED_SOCKET_FAMILIES = tuple(
    sorted(
        {
            int(getattr(socket, name))
            for name in _NETWORK_SOCKET_FAMILY_NAMES
            if hasattr(socket, name)
        }
    )
)


def _check_rc(rc: int, operation: str) -> None:
    if rc < 0:
        raise OSError(-rc, f"{operation} failed")


def install_no_network_filter() -> None:
    lib_name = ctypes.util.find_library("seccomp")
    if not lib_name:
        raise RuntimeError("libseccomp is unavailable")

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        value = ctypes.get_errno()
        raise OSError(value, "PR_SET_NO_NEW_PRIVS failed")

    seccomp = ctypes.CDLL(lib_name, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(ScmpArgCmp),
    ]
    seccomp.seccomp_rule_add_array.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int

    context = seccomp.seccomp_init(SECCOMP_ACT_ALLOW)
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        deny = SECCOMP_ACT_ERRNO_BASE | errno.EPERM
        socket_number = seccomp.seccomp_syscall_resolve_name(b"socket")
        if socket_number < 0:
            raise RuntimeError("socket syscall could not be resolved")
        if not DENIED_SOCKET_FAMILIES:
            raise RuntimeError("no network-capable socket families were resolved")

        for family in DENIED_SOCKET_FAMILIES:
            comparator = ScmpArgCmp(
                arg=0,
                op=SCMP_CMP_EQ,
                datum_a=family,
                datum_b=0,
            )
            _check_rc(
                seccomp.seccomp_rule_add_array(
                    context,
                    deny,
                    socket_number,
                    1,
                    ctypes.byref(comparator),
                ),
                f"seccomp_rule_add_array(socket family={family})",
            )

        io_uring_number = seccomp.seccomp_syscall_resolve_name(b"io_uring_setup")
        if io_uring_number >= 0:
            _check_rc(
                seccomp.seccomp_rule_add(context, deny, io_uring_number, 0),
                "seccomp_rule_add(io_uring_setup)",
            )

        _check_rc(seccomp.seccomp_load(context), "seccomp_load")
    finally:
        seccomp.seccomp_release(context)


def close_inherited_fds() -> None:
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit == resource.RLIM_INFINITY:
        soft_limit = 1_048_576
    os.closerange(3, int(min(soft_limit, 1_048_576)))


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        raise SystemExit("usage: run_with_network_seccomp.py COMMAND [ARG ...]")
    install_no_network_filter()
    close_inherited_fds()
    os.execvpe(args[0], args, os.environ.copy())
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
