# Input validation: bad values must be refused at plan time with a clear message.

mock_provider "hcloud" {}

variables {
  servers = {
    "web-1" = { server_type = "cx22", image = "debian-12" }
  }
  admin_ssh_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample stefan@laptop"]
  admin_cidrs    = ["198.51.100.0/24"]
}

run "ssh_from_the_whole_internet_is_refused" {
  command = plan
  variables {
    admin_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.admin_cidrs]
}

run "ipv6_wildcard_is_refused_too" {
  command = plan
  variables {
    admin_cidrs = ["198.51.100.0/24", "::/0"]
  }
  expect_failures = [var.admin_cidrs]
}

run "open_access_is_possible_when_asked_for_explicitly" {
  command = plan
  variables {
    admin_cidrs             = ["0.0.0.0/0"]
    allow_open_admin_access = true
  }
}

run "empty_admin_cidrs_are_refused" {
  command = plan
  variables {
    admin_cidrs = []
  }
  expect_failures = [var.admin_cidrs]
}

run "malformed_cidr_is_refused" {
  command = plan
  variables {
    admin_cidrs = ["198.51.100.0/33"]
  }
  expect_failures = [var.admin_cidrs]
}

run "a_plain_address_without_a_prefix_is_refused" {
  command = plan
  variables {
    admin_cidrs = ["198.51.100.7"]
  }
  expect_failures = [var.admin_cidrs]
}

run "no_ssh_keys_is_refused" {
  command = plan
  variables {
    admin_ssh_keys = []
  }
  expect_failures = [var.admin_ssh_keys]
}

run "a_private_key_pasted_by_mistake_is_refused" {
  command = plan
  variables {
    admin_ssh_keys = ["-----BEGIN OPENSSH PRIVATE KEY-----"]
  }
  expect_failures = [var.admin_ssh_keys]
}

run "a_multi_line_key_is_refused" {
  command = plan
  variables {
    admin_ssh_keys = ["ssh-ed25519 AAAA\nssh-ed25519 BBBB"]
  }
  expect_failures = [var.admin_ssh_keys]
}

run "no_servers_is_refused" {
  command = plan
  variables {
    servers = {}
  }
  expect_failures = [var.servers]
}

run "more_than_twenty_servers_is_refused" {
  command = plan
  variables {
    servers = { for i in range(21) : "s${i}a" => { server_type = "cx22", image = "debian-12" } }
  }
  expect_failures = [var.servers]
}

run "twenty_servers_are_fine" {
  command = plan
  variables {
    servers = { for i in range(20) : "s${i}a" => { server_type = "cx22", image = "debian-12" } }
  }
}

run "server_names_must_be_valid_host_names" {
  command = plan
  variables {
    servers = { "Web_1" = { server_type = "cx22", image = "debian-12" } }
  }
  expect_failures = [var.servers]
}

run "server_type_must_look_like_a_hetzner_type" {
  command = plan
  variables {
    servers = { "web-1" = { server_type = "CX 22", image = "debian-12" } }
  }
  expect_failures = [var.servers]
}

run "image_must_look_like_an_image_name" {
  command = plan
  variables {
    servers = { "web-1" = { server_type = "cx22", image = "debian 12; rm -rf /" } }
  }
  expect_failures = [var.servers]
}

run "port_22_cannot_be_opened_to_everyone_through_extra_ports" {
  command = plan
  variables {
    extra_tcp_ports = [22]
  }
  expect_failures = [var.extra_tcp_ports]
}

run "ports_must_be_in_range" {
  command = plan
  variables {
    extra_tcp_ports = [70000]
  }
  expect_failures = [var.extra_tcp_ports]
}

run "port_zero_is_refused" {
  command = plan
  variables {
    extra_tcp_ports = [0]
  }
  expect_failures = [var.extra_tcp_ports]
}
