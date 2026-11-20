# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic only: prints how host-name resolution behaves where it runs (on
# the host or inside an AXIS sandbox). Never fails; every check prints a line
# prefixed with "DIAG <where>:".
import ctypes
import errno
import os
import socket
import struct
import subprocess
import sys

where = sys.argv[1] if len(sys.argv) > 1 else "?"
SOCKET = "/run/systemd/resolve/io.systemd.Resolve"


def out(label, value):
    print(f"DIAG {where}: {label}: {value}", flush=True)


def err(exc):
    code = getattr(exc, "errno", None)
    return f"{type(exc).__name__} {errno.errorcode.get(code, code)} {exc}"


try:
    with open("/etc/nsswitch.conf") as conf:
        hosts = [line.strip() for line in conf if line.startswith("hosts:")]
    out("nsswitch hosts", hosts)
except OSError as exc:
    out("nsswitch hosts", err(exc))

out("resolv.conf islink/target", (os.path.islink("/etc/resolv.conf"), os.path.realpath("/etc/resolv.conf")))
try:
    with open("/etc/resolv.conf") as conf:
        lines = [l.strip() for l in conf if l.strip() and not l.startswith("#")]
    out("resolv.conf readable, lines", lines)
except OSError as exc:
    out("resolv.conf", err(exc))

try:
    out("resolver dir listing", sorted(os.listdir(os.path.dirname(SOCKET))))
except OSError as exc:
    out("resolver dir listing", err(exc))

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
try:
    s.connect(SOCKET)
    out("connect resolver socket (nonblocking)", "OK")
    s.setblocking(True)
    s.settimeout(5)
    request = b'{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"_localdnsstub"}}\0'
    s.sendall(request)
    reply = b""
    while not reply.endswith(b"\0"):
        chunk = s.recv(4096)
        if not chunk:
            break
        reply += chunk
    out("varlink ResolveHostname _localdnsstub", reply[:300])
except OSError as exc:
    out("connect/varlink resolver socket", err(exc))
finally:
    s.close()


def dns_query(name):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + qname + struct.pack("!HH", 1, 1)


u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(3)
try:
    u.sendto(dns_query("pypi.org"), ("127.0.0.53", 53))
    out("udp sendto 127.0.0.53 pypi.org", f"{len(u.recv(512))} bytes")
except OSError as exc:
    out("udp sendto 127.0.0.53", err(exc))


class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class msghdr(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p), ("namelen", ctypes.c_uint),
        ("iov", ctypes.POINTER(iovec)), ("iovlen", ctypes.c_size_t),
        ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
        ("flags", ctypes.c_int),
    ]


class mmsghdr(ctypes.Structure):
    _fields_ = [("hdr", msghdr), ("len", ctypes.c_uint)]


libc = ctypes.CDLL(None, use_errno=True)
m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    m.connect(("127.0.0.53", 53))
    payload = dns_query("pypi.org")
    buf = ctypes.create_string_buffer(payload)
    iov = iovec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    msgs = mmsghdr(msghdr(None, 0, ctypes.pointer(iov), 1, None, 0, 0), 0)
    rc = libc.sendmmsg(m.fileno(), ctypes.byref(msgs), 1, 0)
    out("sendmmsg on udp socket", rc if rc >= 0 else f"-1 {errno.errorcode.get(ctypes.get_errno())}")
finally:
    m.close()

for name in ("_localdnsstub", "pypi.org", "github.com"):
    try:
        out(f"getaddrinfo {name}", socket.getaddrinfo(name, 443)[0][4][0])
    except OSError as exc:
        out(f"getaddrinfo {name}", err(exc))

for module in ("resolve", "dns"):
    for options in ("", "single-request"):
        env = dict(os.environ, RES_OPTIONS=options)
        try:
            result = subprocess.run(
                ["getent", "-s", f"hosts:{module}", "ahosts", "pypi.org"],
                env=env, capture_output=True, text=True, timeout=20,
            )
            first = result.stdout.splitlines()[:1]
            out(f"getent -s hosts:{module} pypi.org RES_OPTIONS='{options}'", f"rc={result.returncode} {first}")
        except (OSError, subprocess.SubprocessError) as exc:
            out(f"getent -s hosts:{module}", err(exc))
