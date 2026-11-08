"""Runs the linux_hardening role inside a real Debian 12 container (Ansible controller and target in one) and checks the machine afterwards."""
import re
from collections import defaultdict

import pytest

from docker_helpers import KEY_A, KEY_B, Box, docker_ok, good_vars

pytestmark = pytest.mark.skipif(not docker_ok(), reason="docker is not available")


@pytest.fixture(scope="module")
def box():
    b = Box("vps-kit-linux-%d" % __import__("os").getpid()).start()
    yield b
    b.stop()


def sshd_config(box):
    """sshd -T as {keyword: [values]}; a keyword such as allowusers is printed once per value."""
    d = defaultdict(list)
    for line in box.run("sshd -T 2>/dev/null").stdout.splitlines():
        if " " in line:
            k, v = line.split(" ", 1)
            d[k].append(v)
    return d


def recap(out):
    m = re.search(r"ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)", out)
    return dict(zip(("ok", "changed", "unreachable", "failed", "skipped"), map(int, m.groups()))) if m else None


def test_first_run_configures_and_second_run_changes_nothing(box):
    rc, out = box.play("converge.yml", good_vars())
    assert rc == 0 and recap(out)["changed"] >= 8 and recap(out)["failed"] == 0, out[-1500:]
    rc, out = box.play("converge.yml", good_vars())
    assert rc == 0 and recap(out)["changed"] == 0, "not idempotent:\n" + out[-2500:]


def test_sshd_effective_configuration(box):
    t = {k: v[0] for k, v in sshd_config(box).items()}
    assert t["permitrootlogin"] == "no" and t["passwordauthentication"] == "no" and t["kbdinteractiveauthentication"] == "no"
    assert t["pubkeyauthentication"] == "yes" and t["authenticationmethods"] == "publickey" and t["maxauthtries"] == "3"
    assert sshd_config(box)["allowusers"] == ["stefan"] and t["x11forwarding"] == "no" and t["allowagentforwarding"] == "no" and t["logingracetime"] == "30"


def test_admin_user_has_a_locked_password_sudo_and_exact_key_file(box):
    assert box.run("passwd -S stefan | cut -d' ' -f2").stdout.strip() == "L"
    assert "sudo" in box.run("id -nG stefan").stdout
    assert box.run("stat -c '%a %U:%G' /home/stefan/.ssh /home/stefan/.ssh/authorized_keys").stdout.split("\n")[:2] == ["700 stefan:stefan", "600 stefan:stefan"]
    assert box.run("cat /home/stefan/.ssh/authorized_keys").stdout.strip() == KEY_A


def test_sudoers_file_is_valid_and_root_owned(box):
    assert box.run("visudo -c >/dev/null 2>&1 && echo ok").stdout.strip() == "ok"
    assert box.run("stat -c '%a %U' /etc/sudoers.d/90-hardening-admins").stdout.strip() == "440 root"
    assert "stefan ALL=(ALL) NOPASSWD: ALL" in box.run("cat /etc/sudoers.d/90-hardening-admins").stdout


def test_firewall_ruleset_loads_and_has_the_expected_shape(box):
    r = box.run("nft -f /etc/nftables.conf && nft list ruleset")
    assert r.returncode == 0, r.stdout + r.stderr
    rs = r.stdout
    assert "policy drop" in rs and "ct state established,related accept" in rs
    # nft prints a one-element set without braces, so accept both spellings
    assert re.search(r"ip saddr (\{ )?198\.51\.100\.0/24( \})? tcp dport 22", rs) and re.search(r"ip6 saddr (\{ )?2001:db8::/32( \})? tcp dport 22", rs), rs
    assert "tcp dport 443" in rs
    assert not re.search(r"^\s*tcp dport 22 ", rs, re.M), "SSH must not be open to everyone when CIDRs are set"


def test_fail2ban_updates_sysctl_and_unattended_upgrades_are_in_place(box):
    f2b = box.run("cat /etc/fail2ban/jail.d/10-sshd.local").stdout
    assert "enabled = true" in f2b and "port = 22" in f2b and "198.51.100.0/24" in f2b
    assert 'APT::Periodic::Unattended-Upgrade "1";' in box.run("cat /etc/apt/apt.conf.d/20auto-upgrades").stdout
    sysctl = box.run("cat /etc/sysctl.d/90-hardening.conf").stdout
    assert "net.ipv4.tcp_syncookies = 1" in sysctl and "net.ipv4.conf.all.accept_redirects = 0" in sysctl
    assert box.run("dpkg -s unattended-upgrades fail2ban nftables openssh-server >/dev/null 2>&1 && echo ok").stdout.strip() == "ok"


def test_removing_a_key_from_the_inventory_removes_it_from_the_server(box):
    rc, out = box.play("converge.yml", good_vars(linux_hardening_admin_users=[{"name": "stefan", "ssh_keys": [KEY_B]}]))
    assert rc == 0, out[-1500:]
    keys = box.run("cat /home/stefan/.ssh/authorized_keys").stdout.strip()
    assert keys == KEY_B and KEY_A not in keys


def test_two_keys_and_a_second_user(box):
    users = [{"name": "stefan", "ssh_keys": [KEY_A, KEY_B]}, {"name": "ana", "ssh_keys": [KEY_B], "sudo_nopasswd": False}]
    rc, out = box.play("converge.yml", good_vars(linux_hardening_admin_users=users))
    assert rc == 0, out[-1500:]
    assert box.run("cat /home/stefan/.ssh/authorized_keys").stdout.split("\n")[:2] == [KEY_A, KEY_B]
    sudoers = box.run("cat /etc/sudoers.d/90-hardening-admins").stdout
    assert "stefan ALL=(ALL) NOPASSWD: ALL" in sudoers and "ana ALL=(ALL) ALL" in sudoers and box.run("visudo -c >/dev/null 2>&1 && echo ok").stdout.strip() == "ok"
    assert sshd_config(box)["allowusers"] == ["stefan", "ana"]


def test_extra_ssh_users_and_a_custom_port_are_applied(box):
    rc, out = box.play("converge.yml", good_vars(linux_hardening_ssh_extra_users=["debian"], linux_hardening_ssh_port=2222, linux_hardening_ssh_allow_cidrs=[]))
    assert rc == 0, out[-1500:]
    t = sshd_config(box)
    assert t["port"] == ["2222"] and t["allowusers"] == ["stefan", "debian"]
    assert re.search(r"^\s*tcp dport 2222 ct state new limit rate", box.run("cat /etc/nftables.conf").stdout, re.M), "with no CIDRs the SSH rule applies to everyone, rate limited"
    assert "ignoreip" not in box.run("cat /etc/fail2ban/jail.d/10-sshd.local").stdout


@pytest.mark.parametrize("over,message", [
    ({"linux_hardening_admin_users": []}, "at least one user"),
    ({"linux_hardening_admin_users": [{"name": "stefan"}]}, "at least one ssh key"),
    ({"linux_hardening_admin_users": [{"name": "stefan", "ssh_keys": []}]}, "at least one ssh key"),
    ({"linux_hardening_admin_users": [{"name": "stefan", "ssh_keys": ["not a key"]}]}, "single-line OpenSSH public key"),
    ({"linux_hardening_admin_users": [{"name": "stefan", "ssh_keys": [KEY_A + "\nssh-ed25519 AAAA"]}]}, "single-line OpenSSH public key"),
    ({"linux_hardening_admin_users": [{"name": "Bad Name", "ssh_keys": [KEY_A]}]}, "user names are lowercase"),
    ({"linux_hardening_admin_users": [{"name": "root; rm -rf /", "ssh_keys": [KEY_A]}]}, "user names are lowercase"),
    ({"linux_hardening_admin_users": [{"name": "a", "ssh_keys": [KEY_A]}, {"name": "a", "ssh_keys": [KEY_A]}]}, "names must be unique"),
    ({"linux_hardening_ssh_port": 0}, "1-65535"),
    ({"linux_hardening_ssh_port": 70000}, "1-65535"),
    ({"linux_hardening_ssh_allow_cidrs": ["198.51.100.7"]}, "is not a CIDR"),
    ({"linux_hardening_ssh_allow_cidrs": ["999.1.1.1/24"]}, "is not a CIDR"),
    ({"linux_hardening_ssh_allow_cidrs": ["10.0.0.256/24"]}, "is not a CIDR"),
    ({"linux_hardening_extra_tcp_ports": ["abc"]}, "whole numbers from 1 to 65535"),
    ({"linux_hardening_extra_tcp_ports": [0]}, "whole numbers from 1 to 65535"),
    ({"linux_hardening_extra_tcp_ports": [70000]}, "whole numbers from 1 to 65535"),
    ({"linux_hardening_extra_tcp_ports": [443.5]}, "whole numbers from 1 to 65535"),
    ({"linux_hardening_ssh_allow_cidrs": ["198.51.100.0/24; flush ruleset"]}, "is not a CIDR"),
])
def test_lockout_and_injection_guards_stop_the_run_before_anything_is_changed(box, over, message):
    before = box.run("md5sum /etc/ssh/sshd_config.d/10-hardening.conf /etc/nftables.conf").stdout
    rc, out = box.play("converge.yml", good_vars(**over))
    assert rc != 0, out[-800:]
    if message:
        assert message in out, out[-1200:]
    assert box.run("md5sum /etc/ssh/sshd_config.d/10-hardening.conf /etc/nftables.conf").stdout == before


def test_a_config_that_sshd_itself_rejects_is_never_installed(box):
    """The values pass the role's own checks but sshd refuses them: the validate step must keep the old, working file in place."""
    box.play("converge.yml", good_vars())
    before = box.run("cat /etc/ssh/sshd_config.d/10-hardening.conf").stdout
    rc, out = box.play("converge.yml", good_vars(linux_hardening_ssh_max_auth_tries="many"))
    assert rc != 0
    assert box.run("cat /etc/ssh/sshd_config.d/10-hardening.conf").stdout == before
    assert box.run("sshd -t 2>&1 && echo ok").stdout.strip() == "ok"


def test_invalid_nftables_syntax_is_never_installed(box):
    """Passes the role's own shape checks (hex digits and a prefix) but is not an address nft accepts: nft -c must stop the install."""
    box.play("converge.yml", good_vars())
    before = box.run("cat /etc/nftables.conf").stdout
    rc, out = box.play("converge.yml", good_vars(linux_hardening_ssh_allow_cidrs=["1:2:3:4:5:6:7:8:9::/64"]))
    assert rc != 0 and "nftables ruleset" in out
    assert box.run("cat /etc/nftables.conf").stdout == before
    assert box.run("nft -c -f /etc/nftables.conf && echo ok").stdout.strip() == "ok"


def test_disabling_fail2ban_and_updates_skips_them(box):
    rc, out = box.play("converge.yml", good_vars(linux_hardening_install_fail2ban=False, linux_hardening_auto_updates=False))
    assert rc == 0, out[-1200:]


def test_windows_role_refuses_to_open_rdp_to_the_world_by_accident(box):
    rc, out = box.play("windows_guard.yml", {}, "--tags guard")
    assert rc != 0 and "Set windows_rdp_hardening_allowed_cidrs" in out
    rc, out = box.play("windows_guard.yml", {"windows_rdp_hardening_allowed_cidrs": ["198.51.100.0/24"]}, "--tags guard")
    assert rc == 0, out[-800:]
    rc, out = box.play("windows_guard.yml", {"windows_rdp_hardening_allow_from_anywhere": True}, "--tags guard")
    assert rc == 0, out[-800:]
    rc, out = box.play("windows_guard.yml", {"windows_rdp_hardening_allowed_cidrs": ["198.51.100.0/24"], "windows_rdp_hardening_port": 70000}, "--tags guard")
    assert rc != 0
