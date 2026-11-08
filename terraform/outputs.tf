output "servers" {
  description = "Name, address and image of every server."
  value       = { for name, s in hcloud_server.this : name => { ipv4 = s.ipv4_address, ipv6 = s.ipv6_address, image = s.image } }
}

output "ansible_inventory" {
  description = "Ready for `ansible-playbook -i`: JSON in Ansible's static inventory format."
  value = {
    all = {
      children = {
        linux = {
          hosts = { for name, s in hcloud_server.this : name => { ansible_host = s.ipv4_address } }
        }
      }
    }
  }
}

output "monitor_inventory" {
  description = "Inventory for ZephyraRR/vps-health-monitor: an SSH port check and a Linux node_exporter target for each server."
  value = {
    hosts = [for name, s in hcloud_server.this : {
      name    = name
      address = s.ipv4_address
      labels  = { os = "linux" }
      checks  = [{ type = "tcp", name = "ssh", port = 22 }]
    }]
  }
}
