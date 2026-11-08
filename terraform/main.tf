resource "hcloud_ssh_key" "admin" {
  for_each   = { for i, k in var.admin_ssh_keys : tostring(i) => k }
  name       = "admin-${each.key}"
  public_key = each.value
  labels     = merge(var.labels, { managed-by = "terraform" })
}

resource "hcloud_firewall" "base" {
  name   = "base"
  labels = merge(var.labels, { managed-by = "terraform" })

  rule {
    description = "SSH from the admin addresses only"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.admin_cidrs
  }

  rule {
    description = "ping"
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }

  dynamic "rule" {
    for_each = toset([for p in var.extra_tcp_ports : tostring(p)])
    content {
      description = "public tcp ${rule.value}"
      direction   = "in"
      protocol    = "tcp"
      port        = rule.value
      source_ips  = ["0.0.0.0/0", "::/0"]
    }
  }
}

resource "hcloud_server" "this" {
  for_each     = var.servers
  name         = each.key
  server_type  = each.value.server_type
  image        = each.value.image
  location     = each.value.location
  ssh_keys     = [for k in hcloud_ssh_key.admin : k.id]
  firewall_ids = [hcloud_firewall.base.id]
  user_data    = templatefile("${path.module}/cloud-init.yaml.tftpl", { hostname = each.key })
  labels       = merge(var.labels, { managed-by = "terraform", os = "linux" })

  # Hetzner refuses deletion and rebuild while protected, so a typo in a plan or a stray API call cannot erase a customer's disk.
  # The two flags must be equal.
  delete_protection  = var.protect_servers
  rebuild_protection = var.protect_servers

  lifecycle {
    # cloud-init only runs on first boot; editing the template must not replace running customer servers
    ignore_changes = [user_data]
  }
}
