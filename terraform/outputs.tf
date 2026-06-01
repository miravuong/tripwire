output "role_id" {
  description = "AppRole RoleID for Tripwire. Pair it with a generated SecretID to obtain a token; it is not a credential on its own."
  value       = vault_approle_auth_backend_role.tripwire.role_id
}

output "approle_login_path" {
  description = "Vault API path to exchange a RoleID + SecretID for a token."
  value       = "auth/${vault_auth_backend.approle.path}/login"
}

output "policy_name" {
  description = "Name of the Vault policy attached to the role."
  value       = vault_policy.tripwire.name
}
