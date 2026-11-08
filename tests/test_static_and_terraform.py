"""Lint, syntax checks and the Terraform tests (mock provider). Needs docker."""
import os
import re
import subprocess

import pytest

from docker_helpers import ROOT, Box, docker_ok, sh

pytestmark = pytest.mark.skipif(not docker_ok(), reason="docker is not available")


@pytest.fixture(scope="module")
def box():
    b = Box("vps-kit-static-%d" % os.getpid()).start()
    yield b
    b.stop()


def test_yamllint_is_clean(box):
    r = box.run("cd /work/ansible && yamllint . 2>&1")
    assert r.returncode == 0, r.stdout


def test_ansible_lint_production_profile_is_clean(box):
    r = box.run("cd /work/ansible && ansible-lint --profile production -q 2>&1")
    assert r.returncode == 0, r.stdout[-2000:]


def test_both_playbooks_pass_the_syntax_check_with_the_collections_installed(box):
    r = box.run("cd /work/ansible && ansible-playbook --syntax-check -i inventory.example.yml site.yml 2>&1")
    assert r.returncode == 0 and "playbook:" in r.stdout, r.stdout


def test_example_inventory_loads_and_has_both_groups(box):
    r = box.run("cd /work/ansible && ansible-inventory -i inventory.example.yml --list 2>&1")
    assert r.returncode == 0 and '"linux"' in r.stdout and '"windows"' in r.stdout and "linux_hardening_admin_users" in r.stdout, r.stdout[-800:]


def terraform(script):
    tf = os.path.join(ROOT, "terraform")
    return sh("docker", "run", "--rm", "-v", tf + ":/work", "-w", "/work", "--entrypoint", "sh", "hashicorp/terraform:latest", "-c",
              "terraform init -backend=false -input=false >/tmp/init.log 2>&1 || (cat /tmp/init.log; exit 1); " + script + "; rc=$?; rm -rf .terraform .terraform.lock.hcl; exit $rc", timeout=600)


def test_terraform_is_valid_and_formatted():
    r = terraform("terraform validate -no-color && terraform fmt -check -recursive")
    assert r.returncode == 0, r.stdout + r.stderr


def test_terraform_tests_with_a_mock_provider_all_pass():
    r = terraform("terraform test -no-color")
    out = r.stdout + r.stderr
    m = re.search(r"Success! (\d+) passed, 0 failed", out)
    assert r.returncode == 0 and m and int(m.group(1)) >= 27, out[-2500:]


def test_terraform_refuses_ssh_from_anywhere_when_the_validation_is_removed_the_tests_notice():
    """Mutation check: weaken the rule on purpose and the test suite must go red."""
    path = os.path.join(ROOT, "terraform", "variables.tf")
    original = open(path, encoding="utf-8", newline="").read()
    weak = original.replace("var.allow_open_admin_access || !anytrue", "true || !anytrue")
    assert weak != original
    try:
        open(path, "w", encoding="utf-8", newline="").write(weak)
        r = terraform("terraform test -no-color")
    finally:
        open(path, "w", encoding="utf-8", newline="").write(original)
    assert r.returncode != 0 and "ssh_from_the_whole_internet_is_refused" in r.stdout + r.stderr
