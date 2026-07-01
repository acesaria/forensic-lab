from __future__ import annotations

import argparse
import ctypes
import os
import socket
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid-path", required=True)
    parser.add_argument("--summary-path", required=True)
    parser.add_argument("--hook-log-path", required=True)
    parser.add_argument("--expected-source-port", type=int, required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--duration", type=float, default=600.0)
    args = parser.parse_args()

    Path(args.pid_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.summary_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.hook_log_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.pid_path).write_text(f"{os.getpid()}\n", encoding="utf-8")

    started = time.time()
    peer = ("unknown", 0)
    data = b""
    accept_error = ""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(1)
        libc = ctypes.CDLL(None, use_errno=True)
        storage = ctypes.create_string_buffer(128)
        storage_len = ctypes.c_uint32(len(storage))
        fd = libc.accept(server.fileno(), ctypes.byref(storage), ctypes.byref(storage_len))
        if fd < 0:
            err = ctypes.get_errno()
            accept_error = f"OSError:{err}:{os.strerror(err)}"
        else:
            conn = socket.socket(fileno=fd)
            with conn:
                try:
                    peer = conn.getpeername()
                except OSError:
                    peer = ("unknown", 0)
                data = conn.recv(128)
                conn.sendall(b"father-lab-accept-observed\n")

    summary = (
        f"pid={os.getpid()}\n"
        f"listen={args.host}:{args.port}\n"
        f"peer={peer[0]}:{peer[1]}\n"
        f"accept_error={accept_error}\n"
        f"received={data.decode('utf-8', errors='replace').strip()}\n"
    )
    Path(args.summary_path).write_text(summary, encoding="utf-8")
    source_port_matched = peer[1] == args.expected_source_port or accept_error.startswith("OSError:103:")
    Path(args.hook_log_path).write_text(
        "forensic_lab_accept_wrapper_observed\n"
        f"peer={peer[0]}:{peer[1]}\n"
        f"expected_source_port={args.expected_source_port}\n"
        f"source_port_matched={source_port_matched}\n"
        f"password_matched={data.decode('utf-8', errors='replace').strip() == args.password}\n"
        f"accept_error={accept_error}\n"
        f"father_accept_hook_returned_abort={bool(accept_error)}\n"
        "father_source_repository_patched=false\n"
        "shell_spawned=false\n",
        encoding="utf-8",
    )

    remaining = max(0.0, args.duration - (time.time() - started))
    time.sleep(remaining)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
