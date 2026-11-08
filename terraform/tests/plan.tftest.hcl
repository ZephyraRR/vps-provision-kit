# Runs against a mock provider: no Hetzner account, no network calls to the API, nothing is created.

mock_provider "hcloud" {
  # the real firewall id is a number (as text); the mock would otherwise invent a random word
  mock_resource "hcloud_firewall" {
    defaults = {
      id = "12345"
    }
  }
  mock_resource "hcloud_server" {
    defaults = {
      ipv4_address = "203.0.113.10"
      ipv6_address = "2001:db8::1"
    }
  }
}

variables {
  servers = {
    "web-1" = { server_type = "cx22", image = "debian-12" }
    "db-1"  = { server_type = "cpx31", image = "debian-12", location = "nbg1" }
  }
  admin_ssh_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample stefan@laptop"]
  admin_cidrs    = ["198.51.100.0/24", "2001:db8:100::/48"]
}

run "creates_one_server_per_entry_with_the_requested_size_image_and_location" {
  command = plan
  assert {
    condition     = length(hcloud_server.this) == 2
    error_message = "expected two servers"
  }
  assert {
    condition     = hcloud_server.this["db-1"].server_type == "cpx31" && hcloud_server.this["db-1"].location == "nbg1" && hcloud_server.this["web-1"].location == "fsn1"
    error_message = "size or location not applied (default location should be fsn1)"
  }
  assert {
    condition     = alltrue([for s in hcloud_server.this : s.image == "debian-12"])
    error_message = "image not applied"
  }
}

run "ssh_is_open_only_to_the_admin_addresses" {
  command = plan
  assert {
    condition     = length([for r in hcloud_firewall.base.rule : r if r.port == "22"]) == 1
    error_message = "there must be exactly one rule for port 22"
  }
  assert {
    condition     = alltrue([for r in hcloud_firewall.base.rule : toset(r.source_ips) == toset(var.admin_cidrs) if r.port == "22"])
    error_message = "SSH must be reachable from admin_cidrs only"
  }
  assert {
    condition     = !anytrue([for r in hcloud_firewall.base.rule : contains(r.source_ips, "0.0.0.0/0") if r.port == "22"])
    error_message = "SSH is open to the world"
  }
}

run "no_extra_ports_by_default" {
  command = plan
  assert {
    condition     = length([for r in hcloud_firewall.base.rule : r if r.protocol == "tcp"]) == 1
    error_message = "only SSH should be open by default"
  }
}

run "extra_ports_are_opened_to_everyone_and_nothing_else" {
  command = plan
  variables {
    extra_tcp_ports = [443, 8443]
  }
  assert {
    condition     = toset([for r in hcloud_firewall.base.rule : r.port if r.protocol == "tcp"]) == toset(["22", "443", "8443"])
    error_message = "unexpected open ports"
  }
}

run "servers_are_protected_against_deletion_and_rebuild_by_default" {
  command = plan
  assert {
    condition     = alltrue([for s in hcloud_server.this : s.delete_protection && s.rebuild_protection])
    error_message = "protection must default to on"
  }
}

run "protection_can_be_switched_off_for_a_deliberate_reimage" {
  command = plan
  variables {
    protect_servers = false
  }
  assert {
    condition     = alltrue([for s in hcloud_server.this : !s.delete_protection && !s.rebuild_protection])
    error_message = "protection should be off"
  }
}

run "first_boot_config_turns_password_logins_off_and_sets_the_hostname" {
  command = plan
  assert {
    condition     = strcontains(hcloud_server.this["web-1"].user_data, "PasswordAuthentication no") && strcontains(hcloud_server.this["web-1"].user_data, "hostname: web-1") && strcontains(hcloud_server.this["db-1"].user_data, "hostname: db-1")
    error_message = "cloud-init is missing the baseline"
  }
}

run "every_key_is_registered" {
  command = plan
  variables {
    admin_ssh_keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample a@x",
      "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBExampleExample b@x",
    ]
  }
  assert {
    condition     = length(hcloud_ssh_key.admin) == 2
    error_message = "both keys should be registered"
  }
}

run "outputs_feed_ansible_and_the_monitor" {
  command = apply
  assert {
    condition     = output.ansible_inventory.all.children.linux.hosts["web-1"].ansible_host == "203.0.113.10"
    error_message = "ansible inventory is wrong"
  }
  assert {
    condition     = length(output.monitor_inventory.hosts) == 2 && alltrue([for h in output.monitor_inventory.hosts : h.labels.os == "linux" && h.checks[0].port == 22 && h.address == "203.0.113.10"])
    error_message = "monitor inventory is wrong"
  }
  assert {
    condition     = toset([for h in output.monitor_inventory.hosts : h.name]) == toset(["web-1", "db-1"])
    error_message = "monitor inventory names are wrong"
  }
}
