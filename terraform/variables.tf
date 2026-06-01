variable "vault_address" {
  description = "Vault server address. Leave null to use the VAULT_ADDR environment variable."
  type        = string
  default     = null
}

variable "manage_secret_mount" {
  description = "Whether Terraform creates the KV v2 secrets engine. Set false if the mount already exists (e.g. the default 'secret/' on a dev server) or is managed elsewhere."
  type        = bool
  default     = true
}

variable "secret_mount_path" {
  description = "Path of the KV v2 secrets engine. Must match the paths in vault/policies/tripwire.hcl (currently 'secret/...')."
  type        = string
  default     = "secret"
}

variable "policy_name" {
  description = "Name of the Vault policy granting Tripwire access to its secrets."
  type        = string
  default     = "tripwire"
}

variable "approle_path" {
  description = "Mount path for the AppRole auth backend."
  type        = string
  default     = "approle"
}

variable "role_name" {
  description = "Name of the AppRole role Tripwire authenticates as."
  type        = string
  default     = "tripwire"
}

# TTLs are expressed in seconds (the provider's unit). Defaults mirror
# vault/roles/tripwire-role.json: 1h / 4h / 24h, 20 SecretID uses.
variable "token_ttl" {
  description = "Default TTL in seconds for tokens issued to the role (3600 = 1h)."
  type        = number
  default     = 3600
}

variable "token_max_ttl" {
  description = "Maximum TTL in seconds for tokens issued to the role (14400 = 4h)."
  type        = number
  default     = 14400
}

variable "secret_id_ttl" {
  description = "TTL in seconds for SecretIDs generated for the role (86400 = 24h)."
  type        = number
  default     = 86400
}

variable "secret_id_num_uses" {
  description = "Number of times a SecretID can be used before it expires (0 = unlimited)."
  type        = number
  default     = 20
}
