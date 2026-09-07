#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import resource
import sys
from collections.abc import Sequence

PR_SET_NO_NEW_PRIVS = 38
SECCOMP_ACT_ALLOW = 0x7FFF0000
SECCOMP_ACT_ERRNO_BASE = 0x00050000

# Deny every ordinary networking entry point used by Python/native HTTP clients.
# io_uring_setup is also denied so a process cannot bypass connect(2) using
# IORING_OP_CONNECT. socketpair is deliberately left available for local IPC.
DENIED_SYSCALLS = (
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
    "getpeername",
    "getsockname",
    "io_uring_setup",
)


def _check_rc(rc: int, operation: str) -> None:
    if rc < 0:
        raise OSError(-rc, f"{operation} failed")


def install_no_network_filter() -> None:
    lib_name = ctypes.util.find_library("seccomp")
    if not lib_name:
        raise RuntimeError("libseccomp is unavailable")

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
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
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int

    context = seccomp.seccomp_init(SECCOMP_ACT_ALLOW)
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        deny = SECCOMP_ACT_ERRNO_BASE | errno.EPERM
        resolved = 0
        for name in DENIED_SYSCALLS:
            number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                continue
            _check_rc(
                seccomp.seccomp_rule_add(context, deny, number, 0),
                f"seccomp_rule_add({name})",
            )
            resolved += 1
        if resolved < 8:
            raise RuntimeError(f"too few network syscalls resolved: {resolved}")
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
