import json
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import reimage  # noqa: E402


class MockHetzner:
    """The three endpoints reimage.py uses. `polls_to_finish`: how many GETs of the action report 'running' first."""

    def __init__(self, servers, polls_to_finish=2, mode=""):
        self.servers, self.polls_to_finish, self.mode = servers, polls_to_finish, mode
        self.requests, self.polls = [], 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n)) if n else None
                u = urlparse(self.path)
                outer.requests.append((method, u.path, body))
                if self.headers.get("Authorization") != "Bearer good-token":
                    return self._send(401, {"error": {"code": "unauthorized", "message": "unable to authenticate"}})
                if method == "GET" and u.path == "/servers":
                    name = parse_qs(u.query).get("name", [None])[0]
                    return self._send(200, {"servers": [s for s in outer.servers if name is None or s["name"] == name]})
                m = re.fullmatch(r"/servers/(\d+)/actions/rebuild", u.path)
                if method == "POST" and m:
                    if outer.mode == "locked":
                        return self._send(423, {"error": {"code": "locked", "message": "server is locked"}})
                    return self._send(201, {"action": {"id": 77, "status": "running"}})
                m = re.fullmatch(r"/actions/(\d+)", u.path)
                if method == "GET" and m:
                    outer.polls += 1
                    if outer.mode == "never":
                        return self._send(200, {"action": {"id": 77, "status": "running", "progress": 10}})
                    if outer.mode == "fail":
                        return self._send(200, {"action": {"id": 77, "status": "error", "error": {"code": "action_failed", "message": "image not found"}}})
                    st = "success" if outer.polls > outer.polls_to_finish else "running"
                    return self._send(200, {"action": {"id": 77, "status": st, "progress": 100 if st == "success" else 50}})
                return self._send(404, {"error": {"code": "not_found", "message": "no route"}})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def posts(self):
        return [r for r in self.requests if r[0] == "POST"]

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def server(name="vps-02", sid=4242, ip="127.0.0.1"):
    return {"id": sid, "name": name, "public_net": {"ipv4": {"ip": ip}}}


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    yield s.getsockname()[1]
    s.close()


@pytest.fixture
def api():
    made = []

    def make(servers=None, **kw):
        m = MockHetzner(servers if servers is not None else [server()], **kw)
        made.append(m)
        return m

    yield make
    for m in made:
        m.stop()


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv("HCLOUD_TOKEN", "good-token")


def run(m, *args, runner=None):
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0) if runner is None else runner(cmd)

    extra = [] if "--port-timeout" in args else ["--port-timeout", "3"]                     # a broken guard must fail fast, not wait ten minutes on a real port
    code = reimage.main(["--api-url", m.url, *extra, *args], runner=fake, sleep=lambda s: None)
    return code, calls


def test_dry_run_shows_the_plan_and_changes_nothing(api, capsys):
    m = api()
    code, calls = run(m, "vps-02", "--image", "debian-12")
    out = capsys.readouterr().out
    assert code == 0 and "ERASED" in out and "Dry run" in out and "--confirm vps-02" in out
    assert m.posts() == [] and calls == []


@pytest.mark.parametrize("confirm", [[], ["--confirm", "wrong"], ["--confirm", "VPS-02"], ["--confirm", ""]])
def test_yes_without_the_exact_server_name_is_refused(api, capsys, confirm):
    m = api()
    code, calls = run(m, "vps-02", "--image", "debian-12", "--yes", *confirm)
    assert code == 1 and "refusing to erase" in capsys.readouterr().err
    assert m.posts() == [] and calls == []


def test_full_run_rebuilds_waits_cleans_known_hosts_and_runs_ansible_for_that_host_only(api, listener, capsys):
    m = api()
    code, calls = run(m, "vps-02", "--image", "debian-12", "--yes", "--confirm", "vps-02", "--port", str(listener), "--inventory", "inv.yml", "--playbook", "pb.yml")
    assert code == 0 and "re-imaged and hardened" in capsys.readouterr().out
    assert m.posts() == [("POST", "/servers/4242/actions/rebuild", {"image": "debian-12"})]
    assert m.polls == 3                                                  # two 'running', then 'success'
    assert calls == [["ssh-keygen", "-R", "127.0.0.1"], ["ansible-playbook", "-i", "inv.yml", "pb.yml", "--limit", "vps-02"]]


def test_playbook_none_skips_ansible(api, listener):
    code, calls = run(api(), "vps-02", "--image", "debian-12", "--yes", "--confirm", "vps-02", "--port", str(listener), "--playbook", "none")
    assert code == 0 and not any(c[0] == "ansible-playbook" for c in calls)


def test_ansible_failure_is_reported_as_not_hardened(api, listener, capsys):
    code, _ = run(api(), "vps-02", "--image", "debian-12", "--yes", "--confirm", "vps-02", "--port", str(listener),
                  runner=lambda cmd: SimpleNamespace(returncode=2 if cmd[0] == "ansible-playbook" else 0))
    assert code == 4 and "NOT hardened" in capsys.readouterr().err


def test_failed_action_exits_2_with_the_api_message(api, capsys):
    code, calls = run(api(mode="fail"), "vps-02", "--image", "nope-os", "--yes", "--confirm", "vps-02")
    assert code == 2 and "image not found" in capsys.readouterr().err and calls == []


def test_rebuild_that_never_finishes_times_out(api):
    clock = iter(range(0, 10000, 400))
    m = api(mode="never")
    api_obj = reimage.Api(m.url, "good-token")
    with pytest.raises(reimage.ApiError, match="did not finish within 900 seconds"):
        reimage.wait_action(api_obj, 77, 900, sleep=lambda s: None, clock=lambda: next(clock))


def test_locked_server_is_a_clear_api_error(api, capsys):
    code, _ = run(api(mode="locked"), "vps-02", "--image", "debian-12", "--yes", "--confirm", "vps-02")
    assert code == 2 and "locked" in capsys.readouterr().err


def test_wrong_token_is_a_clear_api_error(api, capsys, monkeypatch):
    monkeypatch.setenv("HCLOUD_TOKEN", "bad")
    code, _ = run(api(), "vps-02", "--image", "debian-12")
    assert code == 2 and "unauthorized" in capsys.readouterr().err


def test_missing_token(api, capsys, monkeypatch):
    monkeypatch.delenv("HCLOUD_TOKEN")
    code, _ = run(api(), "vps-02", "--image", "debian-12")
    assert code == 1 and "HCLOUD_TOKEN" in capsys.readouterr().err


def test_unknown_and_duplicate_server_names(api, capsys):
    assert run(api(), "ghost", "--image", "debian-12")[0] == 2 and "no server named" in capsys.readouterr().err
    two = api([server(sid=1), server(sid=2)])
    assert run(two, "vps-02", "--image", "debian-12")[0] == 2 and "more than one" in capsys.readouterr().err


@pytest.mark.parametrize("name,image", [("../etc", "debian-12"), ("a b", "debian-12"), ("vps;rm -rf", "debian-12"), ("vps-02", "deb ian"), ("vps-02", "x$(id)")])
def test_dangerous_names_never_reach_the_api(api, name, image, capsys):
    m = api()
    code, calls = run(m, name, "--image", image, "--yes", "--confirm", name)
    assert code == 1 and m.requests == [] and calls == []


def test_port_that_never_opens_exits_3_and_does_not_run_ansible(api, capsys):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    closed = s.getsockname()[1]
    s.close()
    code, calls = run(api(), "vps-02", "--image", "debian-12", "--yes", "--confirm", "vps-02", "--port", str(closed), "--port-timeout", "1")
    assert code == 3 and "did not open" in capsys.readouterr().err and calls == []


def test_server_without_public_ipv4_is_refused_after_confirmation(api, capsys):
    m = api([{"id": 5, "name": "v6only", "public_net": {"ipv4": None}}])
    code, _ = run(m, "v6only", "--image", "debian-12", "--yes", "--confirm", "v6only")
    assert code == 2 and "no public IPv4" in capsys.readouterr().err and m.posts() == []


def test_api_unreachable(capsys):
    code = reimage.main(["--api-url", "http://127.0.0.1:1", "vps-02", "--image", "debian-12"], runner=lambda *a, **k: None, sleep=lambda s: None)
    assert code == 2 and "error:" in capsys.readouterr().err


def test_bad_port_value(api, capsys):
    assert run(api(), "vps-02", "--image", "debian-12", "--port", "70000")[0] == 1


def test_missing_ssh_keygen_is_not_fatal(api, listener):
    m = api()

    def runner(cmd, **kw):
        if cmd[0] == "ssh-keygen":
            raise FileNotFoundError("ssh-keygen")
        return SimpleNamespace(returncode=0)

    code = reimage.main(["--api-url", m.url, "vps-02", "--image", "debian-12", "--yes", "--confirm", "vps-02", "--port", str(listener), "--playbook", "none"], runner=runner, sleep=lambda s: None)
    assert code == 0
