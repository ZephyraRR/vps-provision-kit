import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "vps-kit-ansible:test"


def sh(*args, input=None, timeout=900):
    return subprocess.run(args, capture_output=True, text=True, input=input, timeout=timeout, encoding="utf-8", errors="replace", env={**os.environ, "MSYS_NO_PATHCONV": "1"})


def docker_ok() -> bool:
    try:
        return sh("docker", "version", timeout=20).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def ensure_image():
    if sh("docker", "image", "inspect", IMAGE).returncode != 0:
        r = sh("docker", "build", "-f", os.path.join(ROOT, "docker", "Dockerfile.ansible"), "-t", IMAGE, os.path.join(ROOT, "docker"), timeout=1500)
        assert r.returncode == 0, r.stderr[-800:]


class Box:
    """A throwaway Debian container that is both the Ansible controller and the machine being configured."""

    def __init__(self, name):
        self.name = name

    def start(self):
        ensure_image()
        sh("docker", "rm", "-f", self.name)
        r = sh("docker", "run", "-d", "--name", self.name, "--cap-add", "NET_ADMIN", IMAGE)
        assert r.returncode == 0, r.stderr
        for src, dst in ((os.path.join(ROOT, "ansible"), "/work/"), (os.path.join(ROOT, "tests", "converge.yml"), "/work/ansible/converge.yml"),
                         (os.path.join(ROOT, "tests", "windows_guard.yml"), "/work/ansible/windows_guard.yml"), (os.path.join(ROOT, "tests", ".yamllint"), "/work/ansible/.yamllint")):
            assert sh("docker", "cp", src, self.name + ":" + dst).returncode == 0
        return self

    def stop(self):
        sh("docker", "rm", "-f", self.name)

    def run(self, cmd, input=None, timeout=900):
        return sh("docker", "exec", "-i", self.name, "sh", "-c", cmd, input=input, timeout=timeout)

    def play(self, playbook, extra_vars=None, args=""):
        """Runs a playbook inside the box. Returns (returncode, combined output)."""
        self.run("cat > /tmp/vars.json", input=json.dumps(extra_vars or {}))
        r = self.run("cd /work/ansible && ansible-playbook -i localhost, %s -e @/tmp/vars.json %s 2>&1" % (playbook, args))
        return r.returncode, r.stdout + r.stderr


KEY_A = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKeyAForTestsPlaceholderKeyA stefan@laptop"
KEY_B = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKeyBForTestsPlaceholderKeyB stefan@phone"


def good_vars(**over):
    v = {"linux_hardening_admin_users": [{"name": "stefan", "ssh_keys": [KEY_A]}], "linux_hardening_ssh_allow_cidrs": ["198.51.100.0/24", "2001:db8::/32"], "linux_hardening_extra_tcp_ports": [443]}
    v.update(over)
    return v
