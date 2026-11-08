variable "servers" {
  description = "Servers to create, keyed by name. Linux images only (Hetzner Cloud has no Windows images)."
  type = map(object({
    server_type = string
    image       = string
    location    = optional(string, "fsn1")
  }))

  validation {
    condition     = length(var.servers) >= 1 && length(var.servers) <= 20
    error_message = "Define between 1 and 20 servers (a guard against typos that would create hundreds)."
  }
  validation {
    condition     = alltrue([for name in keys(var.servers) : can(regex("^[a-z][a-z0-9-]{0,40}[a-z0-9]$", name))])
    error_message = "Server names must be lowercase letters, digits and hyphens, starting with a letter (they become host names)."
  }
  validation {
    condition     = alltrue([for s in values(var.servers) : can(regex("^[a-z0-9]+$", s.server_type))])
    error_message = "server_type must look like cx22 or cpx31."
  }
  validation {
    condition     = alltrue([for s in values(var.servers) : can(regex("^[a-z0-9][a-z0-9._-]*$", s.image))])
    error_message = "image must be an image name such as debian-12."
  }
}

variable "admin_ssh_keys" {
  description = "OpenSSH public keys that may log in."
  type        = list(string)

  validation {
    condition     = length(var.admin_ssh_keys) > 0
    error_message = "At least one SSH key is required: password logins are disabled from the first boot."
  }
  validation {
    condition     = alltrue([for k in var.admin_ssh_keys : can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( .*)?$", k))])
    error_message = "Every entry must be a single-line OpenSSH public key."
  }
}

variable "admin_cidrs" {
  description = "Addresses that may reach SSH (office, VPN, bastion)."
  type        = list(string)

  validation {
    condition     = length(var.admin_cidrs) > 0
    error_message = "admin_cidrs must not be empty."
  }
  validation {
    condition     = alltrue([for c in var.admin_cidrs : can(cidrhost(c, 0))])
    error_message = "Every admin_cidrs entry must be a valid CIDR such as 203.0.113.0/24."
  }
  validation {
    condition     = var.allow_open_admin_access || !anytrue([for c in var.admin_cidrs : contains(["0.0.0.0/0", "::/0"], c)])
    error_message = "SSH from the whole internet is refused. Use real addresses, or set allow_open_admin_access = true on purpose."
  }
}

variable "allow_open_admin_access" {
  type    = bool
  default = false
}

variable "extra_tcp_ports" {
  description = "Public TCP ports to open to everyone (for example 443)."
  type        = list(number)
  default     = []

  validation {
    condition     = alltrue([for p in var.extra_tcp_ports : p >= 1 && p <= 65535 && floor(p) == p && p != 22])
    error_message = "Ports must be whole numbers from 1 to 65535, and 22 is managed through admin_cidrs."
  }
}

variable "protect_servers" {
  description = "Turn on Hetzner delete and rebuild protection. Switch it off (and apply) before a deliberate re-image or destroy."
  type        = bool
  default     = true
}

variable "labels" {
  type    = map(string)
  default = {}
}
