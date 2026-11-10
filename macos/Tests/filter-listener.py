#!/usr/bin/env python3
"""Test stand-in for the Axiom daemon's flow event listener.

Listens on /var/run/axiom/filter.sock (root:wheel 0600, as the contract
requires), accepts filter connections and appends every received JSON line to
an output file with a receive timestamp. Exits after --seconds or when the
stop file exists, so it never needs to be killed.

    sudo python3 filter-listener.py --out /tmp/flows.jsonl --seconds 120
"""
import argparse
import json
import os
import select
import socket
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("--socket", default="/var/run/axiom/filter.sock")
p.add_argument("--out", required=True)
p.add_argument("--seconds", type=float, default=120)
p.add_argument("--stop-file", default="/tmp/filter-listener.stop")
a = p.parse_args()

os.makedirs(os.path.dirname(a.socket), mode=0o755, exist_ok=True)
if os.path.exists(a.socket):
    os.unlink(a.socket)
if os.path.exists(a.stop_file):
    os.unlink(a.stop_file)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
old = os.umask(0o177)
srv.bind(a.socket)
os.umask(old)
srv.listen(4)
out = open(a.out, "a", buffering=1)
clients = {}
deadline = time.time() + a.seconds
print(f"listening on {a.socket}", file=sys.stderr)
try:
    while time.time() < deadline and not os.path.exists(a.stop_file):
        r, _, _ = select.select([srv] + list(clients), [], [], 0.5)
        for s in r:
            if s is srv:
                c, _ = srv.accept()
                clients[c] = b""
                out.write(json.dumps({"_listener": "connect", "_t": time.time()}) + "\n")
                continue
            data = s.recv(65536)
            if not data:
                out.write(json.dumps({"_listener": "disconnect", "_t": time.time()}) + "\n")
                del clients[s]
                s.close()
                continue
            buf = clients[s] + data
            *lines, rest = buf.split(b"\n")
            clients[s] = rest
            for line in lines:
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = {"_bad": line.decode(errors="replace")}
                obj["_t"] = time.time()
                out.write(json.dumps(obj) + "\n")
finally:
    srv.close()
    os.unlink(a.socket)
