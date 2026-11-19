#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny axiomd IPC client for Linux: one request over the Unix socket, raw JSON reply.

The daemon speaks the Windows pipe protocol unchanged (newline-delimited JSON envelopes,
docs/LINUX_ARCHITECTURE.md §4). Usage:

    scripts/linux/axipc.py serviceHealth
    scripts/linux/axipc.py capabilities
    scripts/linux/axipc.py snapshot
    AXIOM_IPC_SOCKET=$TMPDIR/axiom/run/axiom.sock scripts/linux/axipc.py serviceHealth '{"foo":1}'

The socket is $AXIOM_IPC_SOCKET or /run/axiom/axiom.sock. Exit code 0 on a reply, 1 on a
transport error, 2 on usage; the reply is printed as returned (indented when it parses).
"""
import json
import os
import socket
import sys
import uuid
from datetime import datetime, timezone

DEFAULT_SOCKET = "/run/axiom/axiom.sock"
MAX_REPLY = 256 * 1024


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    request_type = argv[1]
    payload = json.loads(argv[2]) if len(argv) > 2 else None
    path = os.environ.get("AXIOM_IPC_SOCKET") or DEFAULT_SOCKET
    envelope = {
        "version": 1,
        "id": str(uuid.uuid4()),
        "type": request_type,
        "requestedAtUtc": datetime.now(timezone.utc).isoformat(),
    }
    if payload is not None:
        envelope["payload"] = payload

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(path)
            client.sendall((json.dumps(envelope) + "\n").encode("utf-8"))
            data = b""
            while b"\n" not in data and len(data) < MAX_REPLY:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as error:
        print(f"axipc: {path}: {error}", file=sys.stderr)
        return 1

    line = data.split(b"\n", 1)[0].decode("utf-8", "replace")
    try:
        print(json.dumps(json.loads(line), indent=2))
    except ValueError:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
