"""Re-image a Hetzner Cloud server and bring it back to the hardened baseline.

    export HCLOUD_TOKEN=...
    python scripts/reimage.py vps-02 --image debian-12                          # dry run: shows the plan, changes nothing
    python scripts/reimage.py vps-02 --image debian-12 --yes --confirm vps-02   # does it

Steps: find the server by name, ask the API to rebuild it from the image (this ERASES the disk), wait for the API action to finish, wait for the SSH (or RDP)
port to open, then run the Ansible playbook for that host. The API is Hetzner's documented Cloud API; --api-url lets the tests point it at a mock.
Exit codes: 0 done, 1 refused or bad input, 2 API problem, 3 port never opened, 4 Ansible failed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ApiError(RuntimeError):
    pass


class Api:
    def __init__(self, base: str, token: str, timeout: float = 30.0):
        self.base, self.token, self.timeout = base.rstrip("/"), token, timeout

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode()).get("error", {})
            except ValueError:
                err = {}
            raise ApiError("API %s %s -> HTTP %d %s: %s" % (method, path, e.code, err.get("code", ""), err.get("message", "")))
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ApiError("API %s %s failed: %s" % (method, path, getattr(e, "reason", e)))


def find_server(api: Api, name: str) -> dict:
    res = api.call("GET", "/servers?name=" + name)
    servers = [s for s in res.get("servers", []) if s.get("name") == name]
    if not servers:
        raise ApiError("no server named %r in this project" % name)
    if len(servers) > 1:
        raise ApiError("more than one server is named %r" % name)
    return servers[0]


def wait_action(api: Api, action_id: int, timeout: float, sleep=time.sleep, clock=time.monotonic, interval: float = 3.0) -> None:
    end = clock() + timeout
    while True:
        a = api.call("GET", "/actions/%d" % action_id)["action"]
        if a["status"] == "success":
            return
        if a["status"] == "error":
            e = a.get("error") or {}
            raise ApiError("rebuild failed: %s %s" % (e.get("code", ""), e.get("message", "")))
        if clock() > end:
            raise ApiError("rebuild did not finish within %d seconds (last status %s, progress %s)" % (timeout, a["status"], a.get("progress")))
        sleep(interval)


def wait_port(host: str, port: int, timeout: float, sleep=time.sleep, clock=time.monotonic, interval: float = 3.0) -> bool:
    end = clock() + timeout
    while clock() < end:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            sleep(interval)
    return False


def plan(server: dict, image: str, port: int, playbook: str | None) -> list[str]:
    ip = ((server.get("public_net") or {}).get("ipv4") or {}).get("ip", "?")
    steps = ["rebuild server %r (id %s, %s) from image %r: ALL DATA ON ITS DISK IS ERASED" % (server["name"], server["id"], ip, image),
             "wait for the API action to succeed",
             "wait for TCP port %d on %s" % (port, ip)]
    if playbook:
        steps.append("run ansible-playbook %s --limit %s" % (playbook, server["name"]))
    return steps


def main(argv=None, api_factory=Api, runner=subprocess.run, sleep=time.sleep) -> int:
    p = argparse.ArgumentParser(description="Re-image a Hetzner Cloud server and re-apply the baseline.")
    p.add_argument("name")
    p.add_argument("--image", required=True, help="image name or id, for example debian-12")
    p.add_argument("--port", type=int, default=22, help="port that must open before Ansible runs (22 for Linux, 3389 for Windows)")
    p.add_argument("--playbook", default="ansible/site.yml", help="playbook to run afterwards; 'none' to skip")
    p.add_argument("--inventory", default="ansible/inventory.yml")
    p.add_argument("--api-url", default="https://api.hetzner.cloud/v1")
    p.add_argument("--yes", action="store_true", help="actually do it (without this it is a dry run)")
    p.add_argument("--confirm", default="", help="type the server name again to confirm the data loss")
    p.add_argument("--action-timeout", type=float, default=900)
    p.add_argument("--port-timeout", type=float, default=600)
    a = p.parse_args(argv)

    if not NAME.match(a.name) or not IMAGE.match(a.image):
        print("error: server name and image may only contain letters, digits, '.', '_' and '-'", file=sys.stderr)
        return 1
    if not 1 <= a.port <= 65535:
        print("error: --port must be 1-65535", file=sys.stderr)
        return 1
    token = os.environ.get("HCLOUD_TOKEN", "")
    if not token:
        print("error: set HCLOUD_TOKEN", file=sys.stderr)
        return 1
    playbook = None if a.playbook.lower() == "none" else a.playbook
    api = api_factory(a.api_url, token)
    try:
        server = find_server(api, a.name)
    except ApiError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    steps = plan(server, a.image, a.port, playbook)
    print("Plan:")
    for s in steps:
        print("  - " + s)
    if not a.yes:
        print("Dry run. Add --yes --confirm %s to do it." % a.name)
        return 0
    if a.confirm != a.name:
        print("error: refusing to erase %r: pass --confirm %s" % (a.name, a.name), file=sys.stderr)
        return 1
    ip = ((server.get("public_net") or {}).get("ipv4") or {}).get("ip")
    if not ip:
        print("error: the server has no public IPv4 address to wait on", file=sys.stderr)
        return 2
    try:
        res = api.call("POST", "/servers/%d/actions/rebuild" % server["id"], {"image": a.image})
        wait_action(api, res["action"]["id"], a.action_timeout, sleep)
    except (ApiError, KeyError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print("Rebuild finished. Waiting for port %d on %s ..." % (a.port, ip))
    if not wait_port(ip, a.port, a.port_timeout, sleep):
        print("error: port %d on %s did not open within %d seconds" % (a.port, ip, a.port_timeout), file=sys.stderr)
        return 3
    # the new system has new host keys; the old ones would make SSH refuse the connection
    try:
        runner(["ssh-keygen", "-R", ip], capture_output=True)
    except OSError:
        pass                              # no ssh-keygen on this machine: nothing to clean
    if playbook:
        r = runner(["ansible-playbook", "-i", a.inventory, playbook, "--limit", a.name])
        if r.returncode != 0:
            print("error: ansible-playbook failed with exit code %d; the server is re-imaged but NOT hardened" % r.returncode, file=sys.stderr)
            return 4
    print("Done: %s is re-imaged%s." % (a.name, " and hardened" if playbook else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
