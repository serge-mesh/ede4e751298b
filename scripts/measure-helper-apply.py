#!/usr/bin/env python3
"""Bounded, isolated issue #86 probe. Build the apply-memory Rust example first.

The helper child owns no generated client payloads. Its real server, two Tokio workers,
engine queue, fast worker and fake engine run with MALLOC_ARENA_MAX=2 as in the service.
An external RSS watchdog and address-space limit bound the experiment; neither simulates
a cgroup OOM. No live firewall, root access or third-party Python packages are needed.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import struct
import subprocess
import tempfile
import threading
import time

MAX_FRAME = 1 << 20


def frame(data):
    return json.dumps({"type": "apply", "id": 1, "data": data}, separators=(",", ":")).encode()


def workloads():
    small = frame({"interfaces": [{"name": "br0", "mode": "enforce"}], "static": ["192.0.2.1"]})
    empty_prefix = b'{"type":"apply","id":1,"data":{"static":['
    empty_suffix = b']}}'
    empty_count = (MAX_FRAME - len(empty_prefix) - len(empty_suffix) + 1) // 3
    empty = empty_prefix + b','.join([b'""'] * empty_count) + empty_suffix
    # Both lists respect the existing 131072 raw-entry limit. Duplicates normalise to one net.
    valid = frame({"static": ["::"] * 131072, "exempt": ["::"] * 78500})
    assert len(valid) <= MAX_FRAME
    unique = frame({"static": [f"::{i:x}" for i in range(65536)],
                    "exempt": [f"::{i:x}" for i in range(51900)]})
    escaped = b'{"type":"apply","id":1,"data":{"interfaces":[{"name":"' + b'\\u0061' * 174730 + b'"}]}}'
    return {"small": small, "valid-duplicates": valid, "valid-unique": unique,
            "invalid-empty": empty, "invalid-escaped-name": escaped}


def read_memory(pid):
    fields = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                name, value, _ = line.split()
                fields[name[:-1]] = int(value)
    except FileNotFoundError:
        pass
    return fields


def limited():
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))


def receive(sock):
    def exact(n):
        result = bytearray()
        while len(result) < n:
            part = sock.recv(n - len(result))
            if not part:
                raise ConnectionError("helper closed connection")
            result.extend(part)
        return result
    size, = struct.unpack("!I", exact(4))
    assert size <= MAX_FRAME
    return json.loads(exact(size))


def send(sock, payload):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def queued(binary, payload, wait_ms, rounds, role, reconnect, background_mib, work):
    path = str(work / "helper.sock")
    env = dict(os.environ, MALLOC_ARENA_MAX="2")
    child = subprocess.Popen([str(binary), "serve", path, str(wait_ms), role, str(background_mib)],
                             env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True, preexec_fn=limited)
    stopped = threading.Event()
    peak = 0
    exceeded = False
    deadline_exceeded = False
    deadline = time.monotonic() + wait_ms / 1000 * rounds + 60

    def watch():
        nonlocal peak, exceeded, deadline_exceeded
        while not stopped.wait(0.01):
            peak = max(peak, read_memory(child.pid).get("VmRSS", 0))
            if peak > 128 * 1024:
                exceeded = True
                child.kill()
                return
            if time.monotonic() > deadline:
                deadline_exceeded = True
                child.kill()
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    samples = []
    clients = []
    responses = []

    def control(command):
        child.stdin.write(command + "\n")
        child.stdin.flush()
        return json.loads(child.stdout.readline())

    def connect():
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(wait_ms / 1000 + 10)
        s.connect(path)
        return s

    try:
        ready = json.loads(child.stdout.readline())
        samples.append({"stage": "baseline", **ready["memory"]})
        cap = 2 if role == "admin" else 4
        clients = [connect() for _ in range(cap)]
        for wave in range(rounds):
            active = clients
            with concurrent.futures.ThreadPoolExecutor(max_workers=cap) as pool:
                list(pool.map(lambda s: send(s, payload), active))
                time.sleep(0.1)
                samples.append({"stage": f"wave-{wave}-queued", **control("sample")})
                results = list(pool.map(receive, active))
                responses.append([r.get("data", {}).get("code", r["type"]) for r in results])
            samples.append({"stage": f"wave-{wave}-answered", **control("sample")})
            if reconnect:
                for s in clients:
                    s.close()
                time.sleep(0.05)
                clients = [connect() for _ in range(cap)]
        # The fast path and status use another request on an existing, now idle connection.
        send(clients[-1], b'{"type":"ensure","id":2,"data":{"entries":[]}}')
        assert receive(clients[-1])["type"] == "ensure"
        send(clients[-1], b'{"type":"status","id":3}')
        assert receive(clients[-1])["type"] == "status"
        control("release")
        control("drain")
        samples.append({"stage": "released", **control("sample")})
        child.stdin.write("quit\n")
        child.stdin.flush()
        child.wait(timeout=10)
    finally:
        for s in clients:
            s.close()
        if child.poll() is None:
            child.kill()
        child.wait()
        stopped.set()
        watcher.join()
    return {"samples": samples, "responses": responses, "peak_rss_kib": peak,
            "rss_watchdog_killed": exceeded, "deadline_killed": deadline_exceeded,
            "returncode": child.returncode,
            "timeout_ms": wait_ms, "role": role, "reconnect": reconnect,
            "background_mib": background_mib}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--timeout-ms", type=int, default=200)
    parser.add_argument("--rounds", type=int, choices=range(1, 5), default=3)
    parser.add_argument("--role", choices=["edge", "admin"], default="edge")
    parser.add_argument("--reconnect", action="store_true")
    parser.add_argument("--queue", choices=list(workloads()), default="invalid-empty")
    parser.add_argument("--decode-only", action="store_true")
    parser.add_argument("--background-mib", type=int, choices=[0, 18], default=0)
    parser.add_argument("--expect", choices=["baseline", "hardened"])
    args = parser.parse_args()
    assert 100 <= args.timeout_ms <= 120000
    assert args.timeout_ms * args.rounds < 300000, "stay below the engine watchdog's stall threshold"
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="helper-memory-") as directory:
        work = Path(directory)
        data = workloads()
        decoded = {}
        for name, payload in data.items():
            assert len(payload) <= MAX_FRAME, (name, len(payload))
            path = work / name
            path.write_bytes(payload)
            result = subprocess.run([str(binary), "decode", str(path)], capture_output=True,
                                    text=True, check=True, timeout=15, preexec_fn=limited,
                                    env=dict(os.environ, MALLOC_ARENA_MAX="2"))
            decoded[name] = json.loads(result.stdout)
        if args.expect:
            assert all(decoded[name]["decoded"] for name in ("small", "valid-duplicates", "valid-unique"))
            assert decoded["invalid-empty"]["decoded"] == (args.expect == "baseline"), "unexpected executable revision"
        with binary.open("rb") as executable:
            digest = hashlib.file_digest(executable, "sha256").hexdigest()
        print(json.dumps({"binary_sha256": digest, "decode": decoded}), flush=True)
        if not args.decode_only:
            print(json.dumps({"queue": args.queue, **queued(binary, data[args.queue], args.timeout_ms,
                             args.rounds, args.role, args.reconnect, args.background_mib, work)}), flush=True)


if __name__ == "__main__":
    main()
