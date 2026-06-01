# Tripwire's Vault footprint as code: the KV v2 store its secrets live in, the
# access policy, and the AppRole the service authenticates with. This replaces
# the manual `vault policy write` / role-create steps from the project README.

# KV v2 engine backing the secret/data/tripwire/* paths the policy grants.
resource "vault_mount" "secret" {
  count       = var.manage_secret_mount ? 1 : 0
  path        = var.secret_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV v2 store for Tripwire secrets"
}

# Sourced verbatim from the existing scaffold so it stays the single source of
# truth — edit vault/policies/tripwire.hcl, not a copy.
resource "vault_policy" "tripwire" {
  name   = var.policy_name
  policy = file("${path.module}/../vault/policies/tripwire.hcl")
}

resource "vault_auth_backend" "approle" {
  type = "approle"
  path = var.approle_path
}

resource "vault_approle_auth_backend_role" "tripwire" {
  backend            = vault_auth_backend.approle.path
  role_name          = var.role_name
  token_policies     = [vault_policy.tripwire.name]
  token_ttl          = var.token_ttl
  token_max_ttl      = var.token_max_ttl
  secret_id_ttl      = var.secret_id_ttl
  secret_id_num_uses = var.secret_id_num_uses
}
