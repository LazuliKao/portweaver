"""Process-level regression checks. Build with -Dfrpc=true -Dfrps=true -Dddns=true.

Usage: python tests/service_liveness.py zig-out/bin/portweaver[.exe]
Every child has a bounded wait and is reaped even when an assertion fails.
"""

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def child_path(path):
    if sys.platform != "win32" and binary.endswith(".exe"):
        return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
    return str(path)


def check(binary, directory, name, config, alive):
    path = directory / (name + ".json")
    path.write_text(json.dumps({"projects": [], **config}), encoding="utf-8")
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen([binary, "-c", child_path(path)], stdout=output, stderr=output)
        try:
            try:
                child.wait(timeout=1)
                running = False
            except subprocess.TimeoutExpired:
                running = True
            output.seek(0)
            log = output.read().decode(errors="replace")
            assert running == alive, f"{name}: expected alive={alive}\n{log}"
            if not alive:
                assert child.returncode == 0, f"{name}: abnormal exit\n{log}"
            print("PASS", name)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)


binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    check(binary, directory, "empty", {}, False)
    check(binary, directory, "watch-only", {"watch": True}, True)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    check(binary, directory, "frps-only", {
        "frps_nodes": {"server": {"port": port, "bind_addr": "127.0.0.1"}}
    }, True)
    check(binary, directory, "frpc-only", {
        "frpc_nodes": {"client": {"config_mode": "external_uci", "config_content":
            'serverAddr = "127.0.0.1"\nserverPort = 1\nloginFailExit = false\n'}}
    }, True)
    check(binary, directory, "ddns-only", {
        "ddns": [{"name": "idle", "dns_provider": "cloudflare", "dns_secret": "test",
                  "ipv4_enable": False, "ipv6_enable": False}]
    }, True)
    check(binary, directory, "disabled-only", {
        "frps_nodes": {"server": {"enabled": False, "port": port}}
    }, False)
    check(binary, directory, "failed-only", {
        "frpc_nodes": {"client": {"config_mode": "external_file",
                                   "config_path": child_path(directory / "missing.toml")}}
    }, False)
