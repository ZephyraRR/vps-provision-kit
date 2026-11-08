# vps-provision-kit

Terraform, Ansible and a safe re-image script for small hosting operations: create Linux VPS on Hetzner Cloud with a locked-down firewall, bring any Linux server to a hardened baseline, restrict RDP on Windows servers, and rebuild a customer's server from scratch without typing a destructive command by accident.

## The problem

Small hosts re-image servers all day: a customer breaks their VPS, an image is outdated, a fresh RDP box is needed. Done by hand, every re-image is a chance to forget something: password logins left on, SSH open to the world, the firewall not set, the admin keys not installed. And the dangerous step (rebuild = erase the disk) is one wrong server name away from a very bad day. This kit makes the safe path the default path.

## What is in it

| Part | What it does |
|---|---|
| `terraform/` | Hetzner Cloud servers from a map, one firewall (SSH only from your admin CIDRs, optional public TCP ports), SSH keys, first-boot cloud-init. **Refuses** SSH from `0.0.0.0/0`, empty key lists, malformed keys/CIDRs, more than 20 servers, invalid names. Delete and rebuild protection on by default. Outputs an Ansible inventory and an inventory for [vps-health-monitor](https://github.com/ZephyraRR/vps-health-monitor). |
| `ansible/roles/linux_hardening` | Admin users with locked passwords and key-only SSH (`authorized_keys` is exactly the keys in the inventory, so a removed key stops working), sudo rules checked with `visudo`, an sshd drop-in checked with `sshd -t` before it is installed, an nftables default-drop firewall checked with `nft -c` (SSH only from your CIDRs, rate limited, IPv4 and IPv6), fail2ban, unattended security upgrades, kernel network hardening. Refuses to run in a way that would lock you out. |
| `ansible/roles/windows_rdp_hardening` | RDP with Network Level Authentication and high encryption, idle timeout, the built-in allow-from-anywhere rule off, RDP allowed only from your CIDRs, account lockout policy, Guest disabled, security updates. Refuses to open RDP to the internet unless you say so explicitly. |
| `scripts/reimage.py` | Rebuilds a server through the Hetzner Cloud API and re-applies the baseline. Dry run by default; needs `--yes` **and** the exact server name again; waits for the API action and for the SSH port; clears the old host key; runs Ansible for that one host only. |

## Use

```bash
# 1. servers
cd terraform && cp terraform.tfvars.example terraform.tfvars   # servers, admin_ssh_keys, admin_cidrs
export HCLOUD_TOKEN=...   && terraform init && terraform apply
terraform output -json ansible_inventory > ../ansible/inventory.json

# 2. baseline
cd ../ansible && ansible-playbook -i inventory.json site.yml

# 3. later: re-image one server (turn protect_servers off and apply first)
python scripts/reimage.py vps-02 --image debian-12                          # shows the plan
python scripts/reimage.py vps-02 --image debian-12 --yes --confirm vps-02
```

Roles are configured with `linux_hardening_*` and `windows_rdp_hardening_*` variables (see each role's `defaults/main.yml` and `ansible/inventory.example.yml`). Make sure the account Ansible connects with is one of the admin users or listed in `linux_hardening_ssh_extra_users`, otherwise `AllowUsers` will lock that account out.

## Tests (62 pytest tests plus the Terraform suite)

```bash
pip install -r requirements-dev.txt
python -m pytest -q          # needs docker; the first run builds a 370 MB test image
```

- **31 tests run the Linux role in a real Debian 12 container** (controller and target in one) and then inspect the machine: a second run changes nothing (idempotence), `sshd -T` shows root login and passwords off, the key file has the right owner and mode and contains exactly the configured keys, sudoers is valid, the nft ruleset really loads and has the expected shape, fail2ban, sysctl and update settings are present. Eighteen bad inputs (no users, no keys, a pasted private key, injection attempts in user names and CIDRs, octets above 255, invalid ports) must stop the run **before anything changes**, and a value that passes the role's checks but that sshd or nft rejects must never be installed (the old working file stays). These tests found three real bugs in my first version: an invalid IPv4 octet (999.1.1.1/24) was accepted and only failed at the firewall step, after the SSH change had already been applied; a text port was silently turned into port 0; and the test helper misread multi-user `AllowUsers` output. The first two are fixed in the role. One limit remains: a value that only the firewall check can reject (an exotic IPv6 string) is still caught at that step, so earlier tasks in that run have already been applied.
- **24 tests for `reimage.py`** against a mock of the three Hetzner endpoints it uses: dry run changes nothing, every way of getting the confirmation wrong is refused, the happy path (rebuild, poll, port, `ssh-keygen -R`, Ansible limited to that host), API errors (401, locked server, failed action, unreachable API), timeouts, a port that never opens, Ansible failing (reported as "re-imaged but NOT hardened"), dangerous names that must never reach the API. Disabling the confirmation check on purpose makes the tests fail.
- **27 Terraform tests with a mock provider** (`terraform test`, no account, nothing created): server sizes, locations and images, the firewall rules (SSH only from admin CIDRs, no accidental extra ports, extra ports exactly as requested), protection defaults, cloud-init content, outputs, and 18 input validations that must fail with the right variable. A mutation test weakens the "no SSH from the internet" rule and checks the suite goes red.
- `yamllint`, `ansible-lint --profile production` and `ansible-playbook --syntax-check` are clean, and `terraform validate` and `fmt` pass.

## Limits (honest)

- **Never applied against a real cloud.** Terraform is tested with a mock provider and `reimage.py` with a mock API that follows Hetzner's documented endpoints. Expect to adjust small details (server type names, attribute changes between provider versions) on first contact with the real API.
- **The Windows role has not been run on Windows.** It uses documented `ansible.windows` and `community.windows` modules, passes lint and syntax checks, and its safety check is tested, but its tasks have not run against a Windows Server. Try it on a disposable machine first. Hetzner Cloud has no Windows images, so this kit configures Windows servers you already have (any provider); it does not create them.
- The Linux role targets Debian 12 and Ubuntu 22.04 or newer (the `sshd_config.d` include and nftables). It is tested on Debian 12 in a container without systemd, so service reload and restart handlers were not exercised; they are guarded by `ansible_service_mgr == 'systemd'`.
- There is no monitoring agent in these roles; monitoring lives in [vps-health-monitor](https://github.com/ZephyraRR/vps-health-monitor), and `terraform output monitor_inventory` produces its inventory.
- `reimage.py` rebuilds Linux servers from an image name; protected servers must be unprotected first (by design).

## License

MIT
